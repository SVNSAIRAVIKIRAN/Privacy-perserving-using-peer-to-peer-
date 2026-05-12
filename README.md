# Peer-to-Peer Cloud Computing System!
 System

A lightweight and secure peer-to-peer file sharing platform developed using Python and Flask.  
This project focuses on secure communication between distributed peers while maintaining file privacy, authentication, and basic intrusion detection capabilities.

The system follows a decentralized sharing approach where peers can upload, request, and exchange encrypted files through a hub-coordinated network architecture.

---

## Project Overview

Traditional centralized file sharing systems often depend on a single server, which can become a bottleneck or a single point of failure.  
This project explores a peer-to-peer approach where multiple nodes communicate securely while maintaining better control over shared data.

The application includes:

- Secure peer registration
- File upload and retrieval
- Encrypted file transfer
- Hub-based peer discovery
- AI-assisted intrusion detection monitoring
- Local peer storage handling
- Flask-based web interface

---

## Features

- Peer-to-peer communication architecture
- Secure file sharing workflow
- Encrypted file storage and transfer
- Dynamic peer discovery
- Central coordination hub
- Intrusion detection module
- Lightweight Flask frontend
- SQLite database integration
- Session-based authentication
- Modular Python code structure

---

## Technologies Used

| Technology | Purpose |
|------------|---------|
| Python | Backend Development |
| Flask | Web Framework |
| SQLite | Local Database |
| HTML/CSS | Frontend Interface |
| Cryptography Libraries | Secure File Encryption |
| Machine Learning Logic | Intrusion Detection |

---

## System Architecture

The system consists of:

### Hub Node
The hub manages:
- Peer registrations
- Active peer tracking
- Request routing
- Coordination between peers

### Peer Nodes
Each peer can:
- Upload files
- Request files
- Communicate with other peers
- Store encrypted content locally

### Security Layer
The security module handles:
- Encryption
- Secure communication
- Basic intrusion detection
- Unauthorized request monitoring

---

## Project Structure

```bash
project/
│
├── hub.py
├── peer.py
├── crypto.py
├── store.py
├── ai_intrusion_detection.py
├── requirements.txt
├── templates/
├── static/
├── file_store/
└── p2p.db
```

---

## Installation

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
cd YOUR_REPOSITORY
```

---

### Create Virtual Environment

```bash
python -m venv venv
```

Activate environment:

#### Windows

```bash
venv\Scripts\activate
```

#### Linux/Mac

```bash
source venv/bin/activate
```

---

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Running the Project

### Start Hub

```bash
python hub.py
```

---

### Start Peer Node

Open another terminal:

```bash
python peer.py
```

You can run multiple peers by using different ports.

---

## Security Implementation

This project includes multiple security-focused components:

- Encrypted file handling
- Secure peer interaction
- Request validation
- Session management
- Suspicious activity monitoring
- AI-assisted intrusion detection logic

The intrusion detection component observes unusual peer activity patterns and helps identify abnormal behavior during communication.

---

## Learning Outcomes

This project helped in understanding:

- Distributed systems concepts
- Peer-to-peer communication
- Secure file transfer mechanisms
- Flask backend development
- Encryption fundamentals
- Network coordination models
- Intrusion detection basics

---

## Future Improvements

Possible future enhancements:

- Blockchain-based peer validation
- End-to-end encrypted messaging
- Distributed hash table implementation
- Real-time peer analytics dashboard
- Docker deployment
- Cloud deployment support
- Advanced AI-based threat analysis

---

## Screenshots

Add screenshots of:
- Peer dashboard
- File upload interface
- Hub monitoring page
- Intrusion detection logs

---

## Author

S V N Sai Ravi Kiran [Team leader]
B.Tech – Artificial Intelligence and Data Science

---

## Disclaimer

This project was developed for educational and academic purposes to explore secure peer-to-peer communication concepts and distributed system design.
