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

defmodule Astarte.Device.Connection do
  @moduledoc false
  # This behaviour is used to be able to mock the MQTT Connection

  @type client_id :: String.t()
  @type qos :: 0 | 1 | 2

  @callback start_link(options) :: GenServer.on_start()
            when options: [option],
                 option:
                   {:broker_url, broker_url :: String.t()}
                   | {:client_id, client_id :: client_id()}
                   | {:key_pem, key_pem :: String.t()}
                   | {:certificate_pem, certificate_pem :: String.t()}
                   | {:initial_subscriptions, topics :: [String.t()]}
                   | {:ignore_ssl_errors, ignore_ssl_errors :: boolean()}

  @callback subscribe_sync(client_id(), topics :: [String.t()]) ::
              :ok | {:error, reason :: term()}

  @callback publish_sync(
              client_id :: client_id(),
              topic :: String.t(),
              payload :: term(),
              options
            ) :: :ok | {:error, reason :: term()}
            when options: [option],
                 option: {:qos, qos :: qos()}
end
