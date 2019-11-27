module RedmineAccountPolicy
  module UsersHelperPatch
    # changes link text and adds title text if user is only *temporarily locked* -
    # in other words, changes link text such that administrator can identify which
    # users are fully locked and which users are only locked until their timeout has expired
    def change_status_link(user)
      url = {:controller => 'users',
             :action => 'update',
             :id => user,
             :page => params[:page],
             :status => params[:status],
             :tab => nil}

      counter = $invalid_credentials_cache[user.login.downcase]

      if user.locked? && counter && counter.is_a?(Time) && counter == user.updated_on
        link_to l(:rap_account_locked_due_to_account_policy),
          url.merge(:user => {:status => User::STATUS_ACTIVE}),
          :title => l(:rap_alt_account_locked_due_to_account_policy),
          :method => :put,
          :class => 'icon icon-unlock'
      else
        super(user)
      end
    end
  end
end

UsersHelper.send :prepend, RedmineAccountPolicy::UsersHelperPatch
