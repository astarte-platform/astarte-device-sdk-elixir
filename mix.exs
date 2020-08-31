#
# This file is part of Astarte.
#
# Copyright 2018-2020 Ispirata Srl
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
      version: "0.11.2",
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
      package: package(),
      elixirc_paths: elixirc_paths(Mix.env()),
      dialyzer_ignored_warnings: dialyzer_ignored_warnings()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      mod: {Astarte.Device.Application, []},
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:astarte_core, "~> 0.11.2"},
      {:certifi, "~> 2.5"},
      {:hackney, "~> 1.15"},
      {:jason, "~> 1.1"},
      {:tesla, "~> 1.2"},
      {:tortoise, "~> 0.9"},
      {:x509, "~> 0.5"},
      {:excoveralls, "~> 0.11.1", only: :test},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:mox, "~> 0.5", only: :test},
      {:dialyzex, "~> 1.2.0", only: :dev}
    ]
  end

  defp elixirc_paths(:test), do: ["test/support", "lib"]
  defp elixirc_paths(_), do: ["lib"]

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

  defp package do
    [
      description: "Astarte Elixir device SDK",
      maintainers: ["Riccardo Binetti"],
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => "https://github.com/astarte-platform/astarte-device-sdk-elixir",
        "Documentation" => "http://hexdocs.pm/astarte_device"
      }
    ]
  end
end
