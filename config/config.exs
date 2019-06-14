# This file is responsible for configuring your application
# and its dependencies with the aid of the Mix.Config module.
use Mix.Config

config :tesla, adapter: Tesla.Adapter.Hackney

config :astarte_device,
  connection_mod: Astarte.Device.TortoiseConnection,
  pairing_devices_mod: Astarte.API.Pairing.Devices

import_config "#{Mix.env()}.exs"
