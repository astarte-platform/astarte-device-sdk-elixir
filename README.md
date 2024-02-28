<!--
Copyright 2024 SECO Mind Srl

SPDX-License-Identifier: Apache-2.0
-->

# Astarte Device SDK Elixir

This project allows you to execute a device communication on your Astarte 
cluster.

## Prerequisites

Before you begin, ensure you have a running Astarte cluster either on your local machine or accessible remotely. 
To manually build an Astarte cluster, follow this [guide](https://docs.astarte-platform.org/astarte/latest/010-astarte_in_5_minutes.html). 

Alternatively, you can set up an automated instance on Astarte Cloud [here](https://astarte.cloud/).


## Supported Versions

| Elixir SDK | Astarte |
| ---------- | --------|
| 1.0        | 1.0     |
| 1.1+       | 1.1+    |


## Getting Started

Follow these steps to get started with this project:

1. **Clone the Repository**

   Begin by cloning this repository to your local machine.

```

git clone https://github.com/astarte-platform/astarte-device-sdk-elixir.git
```

2. **Install the Elixir and Erlang Version**

   You can use ASDF to install these versions:

```

asdf install
```

3. **Fetch Dependencies**

   Fetch the project dependencies using the `mix deps.get` command.

```

mix deps.get
```

4. **Compile the Project**

   Compile the project using the `mix compile` command.

```

mix compile
```

5. **Run the Project**

   Run the project using the `iex -S mix` command.

```

iex -S mix
```

You can explore the tools inside by entering the IEx shell and typing 
`h Astarte.Device`.

## Basic Usage

Initialize a device instance

You can easily initialize a device by following the steps below:

##### Device Options

Create a device option variable as follows. Use your parameters taken when you 
have created a device from Astarte Cloud or on astartectl:

```

device_options = [ pairing_url: "https://api.your-astarte-instance/pairing", realm: "realm_name", device_id: "device_id", credentials_secret: "device_secret" ignore_ssl_errors: false, interface_provider: "./path-to/interface.json" ]
```

##### Interacting with Your Realm

To interact with your realm, you can either save the Device PID when starting 
the start_link function or retrieve it later using the get_pid function:

```
{:ok, pid} = Astarte.Device.start_link(device_options)
```

or 
```
pid = Astarte.Device.get_pid("realm_name", "device_id")
```

To send data through your interface, use the set_property or send_datastream 
functions. These functions require four parameters: the device process PID, the 
interface name, the path, and the value you want to send. An optional fifth 
parameter, opts, is also accepted:


```
Astarte.Device.set_property(pid, interface_name, path, value)
Astarte.Device.send_datastream(pid, interface_name, path, value, opts \\ [])
```

## Contributing

We welcome contributions! Please read our [contributing guide](#) for details on
 how to submit pull requests to us.

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE]
(https://github.com/astarte-platform/astarte-device-sdk-elixir/blob/master/LICENSE) 
file for details.
