Rails.application.routes.draw do
    scope module: :api, defaults: {format: :json} do
    %w(v1).each do |version|
      namespace version.to_sym do
        resource :configuration, only: %w(show)
        resource :user_token, path: :token, only: %w(create destroy update)
        resources :users, only: %w(create update show) do
          resources :questions, only: %w(index)
          collection do
            post :forgot_password
            put :reset_password
          end
        end
      end
    end
  end

  namespace :admin do
    # get "/stats" => "stats#stats"
    devise_scope :admin_user do
      get '/stats/:scope' => "stats#stats", as: :admin_stats
    end
  end

  devise_for :admin_users, ActiveAdmin::Devise.config
  ActiveAdmin.routes(self)
  devise_for :users
  post '/signup' => 'splash#signup', as: :splash_signup
  get '/splash' => 'splash#index'
  root 'splash#index'
  get '/setup' => 'setup#index'
  # The priority is based upon order of creation: first created -> highest priority.
  # See how all your routes lay out with "rake routes".

  # You can have the
  #

  # Example of regular route:
  #   get 'products/:id' => 'catalog#view'

  # Example of named route that can be invoked with purchase_url(id: product.id)
  #   get 'products/:id/purchase' => 'catalog#purchase', as: :purchase

  # Example resource route (maps HTTP verbs to controller actions automatically):
  #   resources :products

  # Example resource route with options:
  #   resources :products do
  #     member do
  #       get 'short'
  #       post 'toggle'
  #     end
  #
  #     collection do
  #       get 'sold'
  #     end
  #   end

  # Example resource route with sub-resources:
  #   resources :products do
  #     resources :comments, :sales
  #     resource :seller
  #   end

  # Example resource route with more complex sub-resources:
  #   resources :products do
  #     resources :comments
  #     resources :sales do
  #       get 'recent', on: :collection
  #     end
  #   end

  # Example resource route with concerns:
  #   concern :toggleable do
  #     post 'toggle'
  #   end
  #   resources :posts, concerns: :toggleable
  #   resources :photos, concerns: :toggleable

  # Example resource route within a namespace:
  #   namespace :admin do
  #     # Directs /admin/products/* to Admin::ProductsController
  #     # (app/controllers/admin/products_controller.rb)
  #     resources :products
  #   end
end
