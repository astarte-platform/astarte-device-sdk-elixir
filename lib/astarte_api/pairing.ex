#
# This file is part of Astarte.
#
# Copyright 2019 Ispirata Srl
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

defmodule Astarte.API.Pairing do
  @moduledoc """
  Astarte Pairing API access module.
  """

  @doc """
  Create a client to access Pairing API.

  `pairing_url` is the base URL of the Astarte Pairing API instance the client will connect to, e.g. `https://astarte.api.example.com/pairing` or `http://localhost:4003` for a local installation.

  `realm` is the realm that the API will access

  `opts` is a keyword list of additional options detailed below

  ## Options
    * `:auth_token` - Auth token that will be used as authorization when accessing Pairing API. This can be a JWT to use it with `Astarte.API.Pairing.Agent` or a credentials secret to use it with `Astarte.API.Pairing.Device`.
  """
  @spec client(
          pairing_url :: String.t(),
          realm :: String.t(),
          opts :: Astarte.API.client_options()
        ) ::
          Astarte.API.client()
  def client(pairing_url, realm, opts \\ []) do
    base_url = Path.join([pairing_url, "v1", realm])
    Astarte.API.client(base_url, opts)
  end
end
