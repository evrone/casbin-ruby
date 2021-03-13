# frozen_string_literal: true

RSpec.shared_context 'with policy files' do
  def policy_file(name)
    File.expand_path("files/examples/#{name}/policy", __dir__)
  end

  let(:basic_policy_file) { policy_file('basic') }
  let(:rbac_policy_file) { policy_file('rbac') }
  let(:rbac_with_domains_policy_file) { policy_file('rbac_with_domains') }

  let(:explicit_priority_policy_file) { policy_file('priorities/explicit') }
  let(:implicit_priority_policy_file) { policy_file('priorities/implicit') }
end
