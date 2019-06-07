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

defmodule Astarte.Device.DefaultHandler do
  use Astarte.Device.Handler

  require Logger

  @spec init_state(args :: term()) :: {:ok, nil}
  def init_state(_args) do
    {:ok, nil}
  end

  @spec handle_message(message :: Astarte.Device.Handler.Message.t(), nil) :: {:ok, nil}
  def handle_message(message, state) do
    _ = Logger.info("Message received: #{inspect(message)}")
    {:ok, state}
  end
end
