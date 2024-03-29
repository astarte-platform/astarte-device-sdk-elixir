#
# This file is part of Astarte.
#
# Copyright 2018-2023 SECO Mind Srl
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
      version: "1.1.0",
      elixir: "~> 1.14",
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
      dialyzer: dialyzer_opts(Mix.env())
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
      {:astarte_core, "~> 1.1"},
      {:certifi, "~> 2.5"},
      {:hackney, "~> 1.15"},
      {:jason, "~> 1.1"},
      {:tesla, "~> 1.2"},
      {:tortoise311, "~> 0.11"},
      {:x509, "~> 0.5"},
      {:excoveralls, "~> 0.11.1", only: :test},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:mox, "~> 1.0", only: :test},
      {:dialyxir, "~> 1.3.0", only: [:dev, :test]}
    ]
  end

  defp elixirc_paths(:test), do: ["test/support", "lib"]
  defp elixirc_paths(_), do: ["lib"]

  defp dialyzer_opts(:test) do
    [
      plt_file: {:no_warn, "priv/plts/dialyzer.plt"},
      plt_add_apps: [:ex_unit]
    ]
  end

  defp dialyzer_opts(_env), do: []

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
