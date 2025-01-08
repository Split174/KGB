# KGB 🚀

![logo](./img/logo.png)

~~K~~Cool Geo Blocker 🌍

KGB is a Go application that manages IP filtering based on country codes using `nftables`. It allows you to configure allowed or denied countries, gather metrics on the number of packets and bytes filtered, and expose metrics for Prometheus monitoring. 📊

## Features ✨

- **Country-based IP Filtering**: Easily allow or block IP addresses from specific countries. 🚫
- **Prometheus Metrics**: Collect and expose metrics about the number of packets and bytes filtered, including the last update time and the status of blocked and allowed countries. 📈
- **Periodic Updates**: Automatically update the filtering rules at specified intervals. ⏲️
- **Dynamic Configuration**: Change the allowed or denied countries at runtime using command-line flags. ⚙️

## Requirements 🛠️

- Go (version 1.16 or newer)
- `nftables` installed on your system
- Prometheus (if you wish to collect metrics)

## Installation 🛠️

### For any linux distro download binary

```bash
wget https://github.com/Split174/KGB/releases/download/0.0.1/kgb
chmod +x kgb
```

### For Nixos

1. In configuration.nix download tarball with kgb

```nix
nixpkgs.config = {
   packageOverrides = pkgs: {
      kgbnur = import (builtins.fetchTarball "https://github.com/Split174/nur/archive/master.tar.gz") {
         inherit pkgs;
      };
   };
};
```

2. Add package

```nix
environment.systemPackages = with pkgs; [
   kgbnur.nur
];
```

3. (Optional) Run kgb as systemd service

```nix
systemd.services.kgb = {
   description = "KGB service with specific country allowlist";

   after = ["network.target"];
   wantedBy = ["multi-user.target"];

   path = with pkgs; [
      nftables
      wget
   ];

   serviceConfig = {
      ExecStart = "${pkgs.kgbnur.kgb}/bin/kgb --allow ru,nl";

      User = "root";

      Type = "simple";

      Restart = "always";
      RestartSec = "30s";
   };
};
```

## Usage 🖥️

You can run the application with the following command-line flags:

- `--allow`: Comma-separated list of country codes to allow. ✅
- `--deny`: Comma-separated list of country codes to block. ❌
- `--port`: Port number for the Prometheus metrics endpoint (default is 9000).
- `--timer`: Update interval in minutes (default is 60 minutes).

### Examples 📚

To allow traffic from Russia and Netherlands:

```bash
kgb --allow ru,nl
```

To deny traffic from China and South Korea:

```bash
kgb --deny cn,kr
```

## Contributing 🤝

Contributions are welcome! Please feel free to submit issues or pull requests. 

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some amazing feature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a pull request.
