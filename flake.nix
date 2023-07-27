{
  description = "Clueless";

  outputs = { self, nixpkgs }:
    with import nixpkgs { system = "x86_64-linux"; };
    {
      formatter.x86_64-linux = nixpkgs-fmt;

      packages.x86_64-linux.clueless-trace = stdenv.mkDerivation {
        name = "clueless";
        src = self;
        makeFlags = [ "PREFIX=$(out)" ];
      };
      packages.x86_64-linux.default = self.packages.x86_64-linux.clueless-trace;

      devShells.x86_64-linux.default = mkShell {
        packages = [ clang-tools gdb ];
      };
    };
}
