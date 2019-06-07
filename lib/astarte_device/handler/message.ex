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

defmodule Astarte.Device.Handler.Message do
  @moduledoc """
  Module implementing the `%Astarte.Device.Handler.Message{}` struct.
  """

  @enforce_keys [
    :realm,
    :device_id,
    :interface_name,
    :path_tokens,
    :value
  ]
  defstruct [
    :timestamp
    | @enforce_keys
  ]

  @typedoc """
  A struct representing an incoming Astarte message.

  Mainly used by modules implementing `Astarte.Device.Handler` behaviour
  """
  @type t :: %__MODULE__{
          realm: String.t(),
          device_id: String.t(),
          interface_name: String.t(),
          path_tokens: list(String.t()),
          value: term(),
          timestamp: DateTime.t() | nil
        }
end
