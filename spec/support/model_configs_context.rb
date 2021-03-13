# frozen_string_literal: true

RSpec.shared_context 'with model configs' do
  def model_config(name)
    File.expand_path("files/examples/#{name}/model.conf", __dir__)
  end

  let(:basic_config) { model_config('basic') }
  let(:basic_with_root_config) { model_config('basic_with_root') }
  let(:basic_without_users_config) { model_config('basic_without_users') }
  let(:basic_without_resources_config) { model_config('basic_without_resources') }

  let(:rbac_config) { model_config('rbac') }
  let(:rbac_with_domains_config) { model_config('rbac_with_domains') }
  let(:rbac_with_resource_roles_config) { model_config('rbac_with_resource_roles') }

  let(:abac_config) { model_config('abac') }
  let(:abac_with_eval_config) { model_config('abac_with_eval') }

  let(:rest_config) { model_config('rest') }

  let(:explicit_priority_config) { model_config('priorities/explicit') }
  let(:implicit_priority_config) { model_config('priorities/implicit') }
end
