# network-project-nmap-implementation
Based on the provided code files, here is a suggested README for your project:

This project is a network utility tool designed to perform various network-related tasks such as ICMP ping, traceroute, port scanning, DNS lookups, and handling GET/POST requests through a simulated server.

## Features

- **ICMP Ping**: Check if a host is reachable using ICMP echo requests.
- **Traceroute**: Perform a traceroute to a specified host.
- **Port Scanning**: Scan a range of ports on a specified host.
- **DNS Lookups**: Perform DNS and reverse DNS lookups for a host.
- **Interactive Mode**: Send GET and POST requests using raw sockets.
- **TCP Connection Latency**: Measure the average TCP connection latency to a specific port.
- **Simulated Server**: Handle GET and POST requests and return sample user data.

## Installation

Ensure you have Python installed on your system. Clone the repository and navigate to the project directory:

```sh
git clone https://github.com/taha-najaf/nmap.git
cd nmap
```

## Usage

To run the network utility tool, use the following command structure:

```sh
python nmap.py [host] [options]
```

### Options

- `-p, --ports <range>`: Range of ports to scan (e.g., 20-80).
- `-l, --latency <port>`: Measure port latency for a specific port.
- `-a, --attempts <count>`: Number of attempts to measure port latency (default: 5).
- `-d, --dns`: Perform DNS and reverse DNS lookups for the host.
- `-i, --interactive`: Enter interactive mode for GET and POST requests.
- `-c, --icmp`: Check host reachability using ICMP (ping).
- `-t, --traceroute`: Perform a traceroute to the host.
- `-h, --help`: Show help message and exit.

### Examples

- Scan ports 20 to 80 on the host:

  ```sh
  python nmap.py 192.168.1.1 -p 20-80
  ```

- Measure latency to port 80 on the host with 10 attempts:

  ```sh
  python nmap.py example.com -l 80 -a 10
  ```

- Perform DNS lookups for the host:

  ```sh
  python nmap.py example.com -d
  ```

- Check host reachability using ICMP:

  ```sh
  python nmap.py example.com -c
  ```

- Perform a traceroute to the host:

  ```sh
  python nmap.py example.com -t
  ```

- Enter interactive mode for GET and POST requests:

  ```sh
  python nmap.py -i
  ```

## Simulated Server

A simulated server is provided to handle GET and POST requests. To run the server:

```sh
python server.py
```

The server listens on `http://localhost:8000`.

### Sample GET Request

```
GET /user1 HTTP/1.1
Host: localhost
```

### Sample POST Request

```
POST Alice 30 HTTP/1.1
Host: localhost
```


## Contributors

- [Taha Najaf](https://github.com/taha-najaf)

Please feel free to contribute to this project by submitting pull requests or opening issues.

---

This README provides an overview of your project, its features, installation instructions, usage examples, and information about the simulated server. Adjust it as necessary to better fit your project's specifics.
