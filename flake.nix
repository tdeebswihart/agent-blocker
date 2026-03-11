{
  description = "Claude Code PreToolUse hook that auto-allows safe tool calls and blocks dangerous ones";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        go = pkgs.go_1_26;
        buildGoModule = pkgs.buildGoModule.override { inherit go; };
      in
      {
        packages = {
          agent-blocker = buildGoModule {
            pname = "agent-blocker";
            version = "0.1.0";
            src = ./.;
            vendorHash = "sha256-V4H4K+0fUsxP5gZc1Oj2jwMvhcj/QwIuwKBoE5gUwqQ=";
            subPackages = [ "cmd" ];
            postInstall = ''
              mv $out/bin/cmd $out/bin/agent-blocker
            '';
            meta = {
              description =
                "Claude Code PreToolUse hook that auto-allows safe tool calls and blocks dangerous ones";
              mainProgram = "agent-blocker";
            };
          };
          default = self.packages.${system}.agent-blocker;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [ go pkgs.gopls pkgs.golangci-lint ];
        };
      }
    ) // {
      overlays.default = final: prev: {
        agent-blocker = self.packages.${final.system}.agent-blocker;
      };
    };
}
