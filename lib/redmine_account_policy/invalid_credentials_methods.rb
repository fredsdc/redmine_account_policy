module RedmineAccountPolicy
  module InvalidCredentialsMethods
    # on all post requests (whether user is nonexistent, locked, or otherwise),
    # redirect to signin_path
    def lost_password
      super

      if request.post?
        # if token param exists, this is an update password request, so
        # don't flash the lost password email confirmation
        unless params[:token]
          # if a redirection is already occurring, do not redirect again to avoid
          # DoubleRenderErrors -- only available in Rails 3.2+
          redirect_to signin_path unless performed?
          flash.clear

          flash[:notice] = l(:notice_account_lost_email_sent)
        end
      end
    end

    # adds logic before the basic password_authentication routine occurs
    # ensures that users can unlock themselves if they're in timeout
    # but cannot unlock themselves if they've been locked any other way
    def password_authentication
      user = User.try_to_login(params[:username], params[:password], false)
      user_from_login = User.where("login = ?", params[:username]).first
      @seconds = Setting.plugin_redmine_account_policy['account_lockout_duration'].to_i.minutes
      counter = $invalid_credentials_cache[params[:username]]

      # if the user is locked but not due to the plugin, delete them from the cache (this would only occur
      # if the admin has locked the user intentionally, instead of the plugin doing it automatically)
      if is_locked?(user_from_login) && !temporarily_locked_by_plugin?(user_from_login)
        $invalid_credentials_cache.delete(params[:username])
      end


      # allows users to activate themselves if they are present in the cache and
      # timeout is no longer in effect
      unless counter.nil? || user.nil? || timed_out?(user)
        user.activate! if temporarily_locked_by_plugin?(user)
      end

      # if user is locked, and the lock is due to the plugin, skip the
      # password_authentication routine and go straight to the account_locked
      # method. Also, spoof this behaviour if the user does not actually
      # exist in the database, but should be 'locked out'
      if user_from_login                                  \
        && temporarily_locked_by_plugin?(user_from_login) \
        && timed_out?(user_from_login)                    \
        || (user_from_login.nil? && exists_in_cache_and_timed_out?(params[:username]))

        account_locked(user_from_login,signin_path)
      else
        super
      end

    end


    # changes invalid credentials behaviour such that failed logins can be tracked
    # and users can be timed out on maximum fails reached
    def invalid_credentials
      username = params[:username].downcase
      lockout_duration = Setting.plugin_redmine_account_policy['account_lockout_duration'].to_i
      user_from_login = User.where("login = ?", params[:username]).first
      counter = $invalid_credentials_cache[username]
      # check if username is blank or account policy is diabled
      # also, if a user is *already locked*, but *not* because of failed logins
      # (such that they are not in the invalid credentials cache), don't enter
      # them into the cache (otherwise they can unlock themselves by
      # failing out and entering the right password)
      if username.blank? || lockout_duration == 0 || (counter.nil? && is_locked?(user_from_login))
        # because code already exposes locked accounts, ensure that 'locked account' message is returned on *every attempt*
        # otherwise, attackers can determine passwords of locked accounts
        if (counter.nil? && is_locked?(user_from_login))
          redirect_to signin_path unless performed?
          flash[:error] = l(:notice_account_locked)
        else
          # pass username back to Redmine's default handler
          super
        end
        # now let's deal with invalid passwords
      else
        if counter.nil?
          # first failed attempt
          warn_failure(username, 1)

          # user already failed
        elsif counter.is_a?(Time)
          if counter + @seconds > Time.now.utc && is_locked?(user_from_login)
            warn_lockout_in_effect(username)
          else
            # lockout expired, and login failed again
            # unlock the user here so that the user's updated_on
            # can be correctly updated in the case that the user fails out again
            warn_failure(username, 1)
            user_from_login.activate! if user_from_login
          end
        else
          if is_locked?(user_from_login) && !temporarily_locked_by_plugin?(user_from_login)
            # handles the case in which the user has been locked while
            # in the cache - delete them from the cache and redirect them to the locked page
            $invalid_credentials_cache.delete(username)
            account_locked(user_from_login,signin_path)

          else
            # is counter, not a Time
            counter += 1
            if counter >= Setting.plugin_redmine_account_policy['account_lockout_threshold'].to_i
              user_from_login.lock! if user_from_login
              warn_lockout_starts(username)
            else
              warn_failure(username, counter)
            end
          end
        end
      end
    end

    # adds a warning flash if the user's password is within the password
    # expiry warn range
    def successful_authentication(user)
      super(user)

      @password_max_age = Setting.password_max_age.to_i.days
      warn_threshold = Setting.plugin_redmine_account_policy['password_expiry_warn_days'].to_i

      if days_before_expiry(user) <= warn_threshold && days_before_expiry(user) > 0
        flash[:warning] = l(:rap_mail_subject_warn_expiry, days_left: days_before_expiry(user).to_s)
      end
    end

    def counter_exists_and_is_time?(counter)
      counter && counter.is_a?(Time)
    end

    private

    # if user exists and is locked, return true, else false
    def is_locked?(user)
      user && user.locked?
    end

    # changes lockout message for timed out users
    def account_locked(user,redirect_path)
      users_login = params[:username] || user.login

      # Check if user is locked AND in cache (implication: user was locked due to failed logins)
      # If so, flash lockout message instead of default user locked message
      counter = $invalid_credentials_cache[users_login]

      if temporarily_locked_by_plugin?(user) || exists_in_cache_and_timed_out?(users_login)
        flash_lockout(users_login)
      else
        super(user, signin_path)
      end

    end

    # 1if a user is tracked by the failed login system and is timed out
    def exists_in_cache_and_timed_out?(username)
      counter = $invalid_credentials_cache[params[:username]]
      counter_exists_and_is_time?(counter) && ((counter + @seconds) > Time.now.utc)

    end

    def timed_out?(user)
      counter = $invalid_credentials_cache[user.login.downcase] unless user.nil?
      counter_exists_and_is_time?(counter) && ((counter + @seconds) > Time.now.utc)
    end

    # if user is locked, they're in timeout, and the lock was due to
    # the timeout, return true. Else, return false
    def temporarily_locked_by_plugin?(user)
      counter = $invalid_credentials_cache[user.login.downcase] unless user.nil?
      return (is_locked?(user) && counter_exists_and_is_time?(counter) && counter == user.updated_on)
    end



    def warn_failure(username, counter)
      $invalid_credentials_cache[username] = counter
      flash_failure(counter)
      send_failure_mail(username)
      write_log(username, 'Failed login due to invalid password.')
    end

    def warn_lockout_starts(username)
      user_from_login = User.where("login = ?", username).first

      $invalid_credentials_cache[username] = user_from_login.nil? ? Time.now.utc : user_from_login.updated_on

      flash_lockout(username)

      send_lockout_mail(username)

      write_log(username, 'Login failed - lockout starts.')
    end

    def warn_lockout_in_effect(username)
      flash_lockout(username)

      write_log(username, 'Failed login due to temporary lockout.')
    end

    def flash_failure(counter)
      flash.now[:error] = "#{l(:notice_account_invalid_credentials)}. #{l(:rap_notice_invalid_logins_remaining, trials_left: Setting.plugin_redmine_account_policy['account_lockout_threshold'].to_i - counter)}"
    end

    def flash_lockout(username)
      minutes = ((($invalid_credentials_cache[username] + @seconds) - Time.now.utc) / 60).to_i
      flash.now[:error] = "#{l(:rap_notice_account_lockout)}" \
        " #{l('datetime.distance_in_words.x_minutes', count: minutes)}."
    end

    def send_failure_mail(username)
      return unless Setting.plugin_redmine_account_policy['notify_on_failure'] == 'on'

      user = User.find_by_login(username)
      Mailer.notify_login_failure(user, request.remote_ip).deliver unless user.nil?
    end

    def send_lockout_mail(username)
      user = User.find_by_login(username)
      Mailer.notify_account_lockout(user, request.remote_ip).deliver unless user.nil?
    end

    def is_user?(username)
      user = User.find_by_login(username)
      user
    end

    def write_log(username, log_message)
      log_message << " (#{$invalid_credentials_cache[username]}) for '#{params[:username]}'" \
        "from #{request.remote_ip} at #{Time.now.utc}"
        logger.warn { log_message }
    end
  end
end

AccountController.send :prepend, RedmineAccountPolicy::InvalidCredentialsMethods
