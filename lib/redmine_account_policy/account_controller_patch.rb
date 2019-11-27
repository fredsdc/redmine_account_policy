module RedmineAccountPolicy
  module AccountControllerPatch
    $invalid_credentials_cache = Hash.new

    def self.included(base)
      base.send(:include, DailyCronMethods)
      base.send(:include, InvalidCredentialsMethods)
    end

    module DailyCronMethods
      def run_account_policy_daily_tasks
        Rails.logger.info { "#{Time.now.utc}: Account Policy: Running daily tasks" }

        expire_old_passwords!             # password expiry
        lock_unused_accounts!             # lock unused accounts
        purge_expired_invalid_credentials # failed logins
        send_expiration_warnings          # expiration warnings

        Setting.plugin_redmine_account_policy.update({account_policy_checked_on: Date.today.strftime("%Y-%m-%d")})
      end

      # enable must_change_passwd for all expired users.
      def expire_old_passwords!
        User.where(type: 'User', must_change_passwd: false).each do |user|
          if user.password_expired?
            user.update_attribute(:must_change_passwd, true)
            #send expiration notification email
            Mailer.notify_password_is_expired(user).deliver
          end
        end
      end

      def lock_unused_accounts!
        User.where(type: 'User', status: [User::STATUS_REGISTERED, User::STATUS_ACTIVE]).each do |user|
          if user.account_unused?
            user.update_attribute(:must_change_passwd, true) if user.password_expired?
            user.lock!
          end
        end
      end

      #	This also clears any non-existent usernames/logins.
      #	Non-existent usernames are allowed to avoid exposing valid usernames
      #   (by having a different error message).
      def purge_expired_invalid_credentials
        seconds = Setting.plugin_redmine_account_policy['account_lockout_duration'].to_i.minutes

        # added brackets around conditional, seems to resolve issue thrown
        # where method 'round method of class nil:NilClass" is being called
        $invalid_credentials_cache.delete_if do |username, counter|
          (counter.is_a?(Time) && (counter + seconds) < Time.now.utc)
        end
      end

      def send_expiration_warnings
        @password_max_age = Setting.password_max_age.to_i.days

        @warn_threshold = Setting.plugin_redmine_account_policy['password_expiry_warn_days'].to_i

        # only run on unlocked users
        User.where(type: 'User', status: [User::STATUS_REGISTERED, User::STATUS_ACTIVE]).each do |user|
          # if the user's password is past the expiration warn threshold
          if days_before_expiry(user) <= @warn_threshold && days_before_expiry(user) > 0
            if should_send_warning?(user)
              # send the expiration warning email unless their password has already expired
              send_warning_password_expiry_mail(user) unless user.password_expired?
            end
          end
        end
      end

      def send_warning_password_expiry_mail(user)
        return unless Setting.plugin_redmine_account_policy['password_expiry_warn_days'].to_i > 0

        Mailer.notify_password_warn_expiry(user,
                                           days_before_expiry(user)
                                          ).deliver unless user.nil?
      end

      def days_before_expiry(user)
        (last_change_pwd(user) + @password_max_age - Date.today).to_i
      end

      def last_change_pwd(user)
        (user.passwd_changed_on || user.created_on).to_date
      end

      def already_ran_today?
        last_run = Setting.plugin_redmine_account_policy['account_policy_checked_on']
        last_run == Date.today.strftime("%Y-%m-%d") ? true : false
      end

      def should_send_warning?(user)
        days_left = days_before_expiry(user)
        days_left == @warn_threshold || (@warn_threshold - days_left) % 7 == 0 || days_left == 1
      end
    end
  end

end

AccountController.send :include, RedmineAccountPolicy::AccountControllerPatch
