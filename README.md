# Hello Erlang

A demonstration Erlang project showcasing multiple third-party dependencies using `rebar3`.

## Features
- **JSON Handling**: Uses `jiffy` and `jsx`.
- **Logging**: Implements `lager`.
- **HTTP Client**: Includes `hackney`.
- **Testing**: Uses `EUnit`.

## Prerequisites

You will need the Erlang runtime and `rebar3` (the Erlang build tool) installed on your machine.

### macOS
```bash
brew install erlang rebar3
```

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install erlang rebar3
```

### Windows
The easiest way is via [Chocolatey](https://chocolatey.org/):
```powershell
choco install erlang rebar3
```

## Getting Started

### 1. Install Dependencies
Navigate to the project root and run:
```bash
rebar3 fetch
```

### 2. Compile the Project
```bash
rebar3 compile
```

### 3. Run Tests
Verify the project is working correctly using the EUnit test suite:
```bash
rebar3 eunit
```

### 4. Run the Demo
You can start an interactive Erlang shell with the project loaded and run the demo module:
```bash
rebar3 shell
```

Once inside the Erlang shell (`erl`), run:
```erlang
hello_world_demo:run().
```

## Project Structure
- `src/`: Source code (`.erl` files)
- `test/`: Test suites (`.erl` files using EUnit)
- `rebar.config`: Project configuration and dependencies
```

