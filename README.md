# VARS

**V**ulnerability **A**ssessment **R**eference **S**ystem

## Installing Dependencies

We try to keep a stable development environment. Please use `govendor` to make sure you have the same version of our external packages.

```bash
#Install the govendor tool
go get github.com/kardianos/govendor
#Download the dependencies into the vendoring folder
govendor sync
```
