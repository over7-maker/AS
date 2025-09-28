# The Sovereign Eye - RPKI-Secured & Graph-Driven ASM Core

## The Pinnacle of Enterprise & ISP-Scale Cyber Assurance

The Sovereign Eye is a cloud-native platform that transcends traditional vulnerability scanning by delivering auditable, continuous, and definitive asset visibility at the scale of a major Internet Service Provider (ISP) or the largest global enterprise.

## Key Features

- **Two-Plane Distributed System**: High-throughput architecture with Control and Data planes
- **Attack Path Algebra Engine**: Neo4j-powered graph analysis for attack path visualization
- **RPKI-Secured Scanning**: Routing integrity and lawful scanning at ISP scale
- **Dynamic Risk Prioritization**: CISA KEV and FIRST EPSS integration
- **Zero-Trust Architecture**: HashiCorp Vault integration for secrets management
- **Compliance Automation**: NIST CSF 2.0, CISA BOD 23-01, ISO 27001 alignment

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Control Plane                             │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐        │
│  │ API Gateway │  │ Orchestrator │  │ Workflow Engine│        │
│  └─────────────┘  └──────────────┘  └────────────────┘        │
│         │                 │                    │                │
│  ┌──────────────────────────────────────────────────┐         │
│  │            Message Bus (Kafka/RabbitMQ)          │         │
│  └──────────────────────────────────────────────────┘         │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                        Data Plane                                │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐        │
│  │Worker Nodes │  │Scanner Tools │  │Container Runtime│        │
│  └─────────────┘  └──────────────┘  └────────────────┘        │
│                                                                  │
│  ┌──────────────────────────────────────────────────┐         │
│  │         Data Persistence Layer                    │         │
│  │  PostgreSQL | Elasticsearch | Neo4j | Vault      │         │
│  └──────────────────────────────────────────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Kubernetes cluster (for production)
- Go 1.21+
- Node.js 20+
- Python 3.11+

### Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/sovereign-eye.git
cd sovereign-eye

# Install dependencies
make install-deps

# Start development environment
docker-compose up -d

# Run migrations
make migrate

# Start services
make dev
```

### Production Deployment

See [docs/deployment/](docs/deployment/) for comprehensive deployment guides.

## Documentation

- [Architecture Guide](docs/architecture/)
- [API Reference](docs/api/)
- [Workflow Specifications](docs/workflows/)
- [Security Policies](docs/security/)
- [Compliance Reports](docs/compliance/)

## Security

This platform implements defense-in-depth security controls:

- Supply chain integrity via Sigstore Cosign
- SBOM generation for all components
- Zero-trust networking
- End-to-end encryption
- Multi-tenancy isolation

## License

Proprietary - See LICENSE file for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.