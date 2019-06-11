#
# This file is part of Astarte.
#
# Copyright 2018 Ispirata Srl
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

defmodule Astarte.Device.MixProject do
  use Mix.Project

  def project do
    [
      app: :astarte_device,
      version: "0.11.0-dev",
      elixir: "~> 1.8",
      start_permanent: Mix.env() == :prod,
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
      ],
      deps: deps(),
      dialyzer_ignored_warnings: dialyzer_ignored_warnings()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:astarte_core, github: "astarte-platform/astarte_core"},
      {:certifi, "~> 2.5"},
      {:hackney, "~> 1.15"},
      {:jason, "~> 1.1"},
      {:tesla, "~> 1.2"},
      {:tortoise, "~> 0.9"},
      {:x509, "~> 0.5"},
      {:excoveralls, "~> 0.11.1", only: :test},
      {:dialyzex, "~> 1.2.0", only: :dev}
    ]
  end

  defp dialyzer_ignored_warnings do
    [
      {:warn_matching, {'lib/astarte_device/handler.ex', 82},
       {:pattern_match, ['pattern {\'error\', __@7}', '{\'ok\',\'nil\'}']}},
      # Remove when this https://github.com/gausby/tortoise/pull/110 gets merged
      {:warn_matching, {'lib/astarte_device/impl.ex', :_},
       {:pattern_match,
        [
          'pattern {\'ok\', _pid@1}',
          '{\'error\',\'invalid_args\' | \'invalid_certificate\' | \'invalid_private_key\'}'
        ]}}
    ]
  end
end
