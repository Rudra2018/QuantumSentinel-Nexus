# QuantumSentinel-Nexus Google Cloud Infrastructure
terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }
}

# Variables
variable "project_id" {
  description = "Google Cloud Project ID"
  type        = string
}

variable "region" {
  description = "Google Cloud Region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Google Cloud Zone"
  type        = string
  default     = "us-central1-a"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "prod"
}

# Provider configuration
provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# Enable required APIs
resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
    "run.googleapis.com",
    "cloudbuild.googleapis.com",
    "containerregistry.googleapis.com",
    "sqladmin.googleapis.com",
    "redis.googleapis.com",
    "pubsub.googleapis.com",
    "storage.googleapis.com",
    "secretmanager.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
    "cloudtrace.googleapis.com",
    "aiplatform.googleapis.com"
  ])

  service = each.value
  project = var.project_id

  disable_dependent_services = true
  disable_on_destroy         = false
}

# VPC Network
resource "google_compute_network" "quantum_vpc" {
  name                    = "quantum-sentinel-vpc"
  auto_create_subnetworks = false
  project                 = var.project_id

  depends_on = [google_project_service.apis]
}

# Subnet
resource "google_compute_subnetwork" "quantum_subnet" {
  name          = "quantum-sentinel-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.quantum_vpc.id
  project       = var.project_id

  secondary_ip_range {
    range_name    = "quantum-pods"
    ip_cidr_range = "10.1.0.0/16"
  }

  secondary_ip_range {
    range_name    = "quantum-services"
    ip_cidr_range = "10.2.0.0/16"
  }
}

# VPC Access Connector for Cloud Run
resource "google_vpc_access_connector" "quantum_connector" {
  name          = "quantum-vpc-connector"
  region        = var.region
  project       = var.project_id
  network       = google_compute_network.quantum_vpc.name
  ip_cidr_range = "10.8.0.0/28"

  depends_on = [google_project_service.apis]
}

# Firewall rules
resource "google_compute_firewall" "allow_internal" {
  name    = "quantum-allow-internal"
  network = google_compute_network.quantum_vpc.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  source_ranges = ["10.0.0.0/8"]
}

resource "google_compute_firewall" "allow_ssh" {
  name    = "quantum-allow-ssh"
  network = google_compute_network.quantum_vpc.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["quantum-ssh"]
}

# Cloud SQL PostgreSQL instance
resource "google_sql_database_instance" "quantum_postgres" {
  name             = "quantum-sentinel-postgres"
  database_version = "POSTGRES_15"
  region           = var.region
  project          = var.project_id

  settings {
    tier              = "db-custom-4-16384"
    availability_type = "REGIONAL"
    disk_type         = "PD_SSD"
    disk_size         = 100

    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.quantum_vpc.id
      require_ssl     = true
    }

    database_flags {
      name  = "max_connections"
      value = "200"
    }

    database_flags {
      name  = "shared_preload_libraries"
      value = "pg_stat_statements"
    }
  }

  deletion_protection = true

  depends_on = [
    google_project_service.apis,
    google_service_networking_connection.private_vpc_connection
  ]
}

# Cloud SQL Database
resource "google_sql_database" "quantum_db" {
  name     = "quantum_sentinel"
  instance = google_sql_database_instance.quantum_postgres.name
  project  = var.project_id
}

# Cloud SQL User
resource "google_sql_user" "quantum_user" {
  name     = "quantum_sentinel"
  instance = google_sql_database_instance.quantum_postgres.name
  password = random_password.postgres_password.result
  project  = var.project_id
}

resource "random_password" "postgres_password" {
  length  = 32
  special = true
}

# Private IP allocation for Cloud SQL
resource "google_compute_global_address" "private_ip_alloc" {
  name          = "quantum-private-ip-alloc"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.quantum_vpc.id
  project       = var.project_id
}

# Private VPC connection
resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.quantum_vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_alloc.name]
}

# Redis instance
resource "google_redis_instance" "quantum_redis" {
  name           = "quantum-sentinel-redis"
  tier           = "STANDARD_HA"
  memory_size_gb = 4
  region         = var.region
  project        = var.project_id

  location_id             = var.zone
  alternative_location_id = "${substr(var.region, 0, length(var.region)-1)}b"

  authorized_network = google_compute_network.quantum_vpc.id
  connect_mode       = "PRIVATE_SERVICE_ACCESS"

  redis_version = "REDIS_7_0"
  display_name  = "QuantumSentinel Redis"

  depends_on = [google_project_service.apis]
}

# Cloud Storage buckets
resource "google_storage_bucket" "quantum_reports" {
  name     = "${var.project_id}-quantum-reports"
  location = var.region
  project  = var.project_id

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }
}

resource "google_storage_bucket" "quantum_research_data" {
  name     = "${var.project_id}-quantum-research-data"
  location = var.region
  project  = var.project_id

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type = "Delete"
    }
  }
}

resource "google_storage_bucket" "quantum_ml_models" {
  name     = "${var.project_id}-quantum-ml-models"
  location = var.region
  project  = var.project_id

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }
}

# Pub/Sub topics and subscriptions
resource "google_pubsub_topic" "scan_events" {
  name    = "quantum-scan-events"
  project = var.project_id

  depends_on = [google_project_service.apis]
}

resource "google_pubsub_topic" "vulnerability_alerts" {
  name    = "quantum-vulnerability-alerts"
  project = var.project_id

  depends_on = [google_project_service.apis]
}

resource "google_pubsub_subscription" "scan_events_sub" {
  name    = "quantum-scan-events-sub"
  topic   = google_pubsub_topic.scan_events.name
  project = var.project_id

  ack_deadline_seconds = 300

  push_config {
    push_endpoint = "https://quantum-sentinel-orchestration-${random_id.suffix.hex}-uc.a.run.app/webhooks/scan-events"
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

# Service Account for QuantumSentinel
resource "google_service_account" "quantum_sa" {
  account_id   = "quantum-sentinel-sa"
  display_name = "QuantumSentinel Service Account"
  project      = var.project_id
}

# IAM roles for service account
resource "google_project_iam_member" "quantum_sa_roles" {
  for_each = toset([
    "roles/cloudsql.client",
    "roles/redis.editor",
    "roles/storage.admin",
    "roles/pubsub.admin",
    "roles/secretmanager.secretAccessor",
    "roles/monitoring.metricWriter",
    "roles/logging.logWriter",
    "roles/cloudtrace.agent",
    "roles/aiplatform.user"
  ])

  role    = each.value
  member  = "serviceAccount:${google_service_account.quantum_sa.email}"
  project = var.project_id
}

# Secret Manager secrets
resource "google_secret_manager_secret" "postgres_url" {
  secret_id = "quantum-postgres-url"
  project   = var.project_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "postgres_url_version" {
  secret      = google_secret_manager_secret.postgres_url.id
  secret_data = "postgresql://${google_sql_user.quantum_user.name}:${random_password.postgres_password.result}@${google_sql_database_instance.quantum_postgres.private_ip_address}:5432/${google_sql_database.quantum_db.name}"
}

resource "google_secret_manager_secret" "chaos_api_key" {
  secret_id = "chaos-api-key"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "huggingface_token" {
  secret_id = "huggingface-token"
  project   = var.project_id

  replication {
    auto {}
  }
}

# GKE Cluster for additional workloads
resource "google_container_cluster" "quantum_gke" {
  name     = "quantum-sentinel-cluster"
  location = var.zone
  project  = var.project_id

  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.quantum_vpc.name
  subnetwork = google_compute_subnetwork.quantum_subnet.name

  ip_allocation_policy {
    cluster_secondary_range_name  = "quantum-pods"
    services_secondary_range_name = "quantum-services"
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  addons_config {
    http_load_balancing {
      disabled = false
    }
    horizontal_pod_autoscaling {
      disabled = false
    }
    network_policy_config {
      disabled = false
    }
  }

  network_policy {
    enabled = true
  }

  depends_on = [google_project_service.apis]
}

# GKE Node Pool
resource "google_container_node_pool" "quantum_nodes" {
  name       = "quantum-sentinel-nodes"
  location   = var.zone
  cluster    = google_container_cluster.quantum_gke.name
  node_count = 3
  project    = var.project_id

  node_config {
    preemptible  = false
    machine_type = "e2-standard-4"

    service_account = google_service_account.quantum_sa.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]

    labels = {
      environment = var.environment
      application = "quantum-sentinel"
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }

  autoscaling {
    min_node_count = 1
    max_node_count = 10
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }
}

# Cloud Monitoring
resource "google_monitoring_alert_policy" "high_error_rate" {
  display_name = "QuantumSentinel High Error Rate"
  project      = var.project_id

  conditions {
    display_name = "Error rate too high"

    condition_threshold {
      filter          = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=~\"quantum-sentinel.*\""
      duration        = "300s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 0.05

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  combiner = "OR"

  depends_on = [google_project_service.apis]
}

# Outputs
output "vpc_network" {
  description = "VPC network name"
  value       = google_compute_network.quantum_vpc.name
}

output "postgres_instance" {
  description = "PostgreSQL instance connection name"
  value       = google_sql_database_instance.quantum_postgres.connection_name
}

output "redis_instance" {
  description = "Redis instance connection details"
  value = {
    host = google_redis_instance.quantum_redis.host
    port = google_redis_instance.quantum_redis.port
  }
}

output "storage_buckets" {
  description = "Cloud Storage bucket names"
  value = {
    reports       = google_storage_bucket.quantum_reports.name
    research_data = google_storage_bucket.quantum_research_data.name
    ml_models     = google_storage_bucket.quantum_ml_models.name
  }
}

output "service_account_email" {
  description = "Service account email"
  value       = google_service_account.quantum_sa.email
}

output "gke_cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.quantum_gke.name
}