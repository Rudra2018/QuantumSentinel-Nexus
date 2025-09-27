#!/usr/bin/env python3
"""
QuantumSentinel-Nexus ML Model Management System
Advanced model lifecycle management with Hugging Face integration
"""

import asyncio
import logging
import json
import os
import shutil
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from datetime import datetime, timedelta
import pickle
import torch
import numpy as np
from concurrent.futures import ThreadPoolExecutor
import requests
from packaging import version

# Hugging Face imports
from huggingface_hub import HfApi, HfFolder, Repository, snapshot_download
from transformers import (
    AutoConfig, AutoTokenizer, AutoModel, AutoModelForSequenceClassification,
    TrainingArguments, Trainer, pipeline
)
import datasets
from datasets import Dataset, DatasetDict

@dataclass
class ModelInfo:
    """Model information and metadata"""
    name: str
    version: str
    model_type: str
    task: str
    model_path: str
    config_path: str
    last_updated: datetime
    size_mb: float
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    inference_time_ms: float
    memory_usage_mb: float
    is_fine_tuned: bool
    base_model: str
    training_data_hash: str
    model_hash: str

@dataclass
class TrainingConfig:
    """Training configuration for model fine-tuning"""
    model_name: str
    task_type: str
    training_data_path: str
    validation_data_path: str
    output_dir: str
    num_epochs: int
    batch_size: int
    learning_rate: float
    warmup_steps: int
    weight_decay: float
    save_steps: int
    eval_steps: int
    logging_steps: int
    max_seq_length: int
    gradient_accumulation_steps: int

class MLModelManager:
    """Comprehensive ML model management system"""

    def __init__(self, models_dir: str = "./models", config_path: str = None):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(exist_ok=True)
        self.config = self._load_config(config_path)
        self.logger = logging.getLogger(__name__)
        self.hf_api = HfApi()
        self.executor = ThreadPoolExecutor(max_workers=4)

        # Model registry
        self.model_registry = {}
        self.active_models = {}
        self.training_jobs = {}

        # Initialize model registry
        self._initialize_model_registry()

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load model management configuration"""
        default_config = {
            "auto_update_models": True,
            "update_check_interval_hours": 24,
            "max_model_cache_size_gb": 50,
            "enable_model_compression": True,
            "enable_quantization": True,
            "training_data_retention_days": 30,
            "model_backup_enabled": True,
            "huggingface_cache_dir": "./models/hf_cache",
            "custom_models_dir": "./models/custom",
            "fine_tuned_models_dir": "./models/fine_tuned",
            "model_versions_to_keep": 3,
            "auto_fine_tune": False,
            "performance_monitoring": True
        }

        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)

        return default_config

    def _initialize_model_registry(self):
        """Initialize the model registry with available models"""
        registry_file = self.models_dir / "registry.json"

        if registry_file.exists():
            with open(registry_file, 'r') as f:
                self.model_registry = json.load(f)
        else:
            self.model_registry = self._create_default_registry()
            self._save_registry()

    def _create_default_registry(self) -> Dict[str, Any]:
        """Create default model registry"""
        return {
            "vulnerability_detection": {
                "models": {
                    "code_vulnerability": {
                        "model_name": "microsoft/codebert-base",
                        "task": "sequence_classification",
                        "description": "General code vulnerability detection",
                        "fine_tuned": False,
                        "last_updated": None,
                        "performance_metrics": {}
                    },
                    "sql_injection": {
                        "model_name": "huggingface/CodeBERTa-small-v1",
                        "task": "sequence_classification",
                        "description": "SQL injection vulnerability detection",
                        "fine_tuned": False,
                        "last_updated": None,
                        "performance_metrics": {}
                    },
                    "xss_detection": {
                        "model_name": "distilbert-base-uncased",
                        "task": "sequence_classification",
                        "description": "XSS vulnerability detection",
                        "fine_tuned": False,
                        "last_updated": None,
                        "performance_metrics": {}
                    },
                    "api_security": {
                        "model_name": "microsoft/GraphCodeBERT-base",
                        "task": "feature_extraction",
                        "description": "API security vulnerability analysis",
                        "fine_tuned": False,
                        "last_updated": None,
                        "performance_metrics": {}
                    },
                    "business_logic": {
                        "model_name": "sentence-transformers/all-MiniLM-L6-v2",
                        "task": "feature_extraction",
                        "description": "Business logic vulnerability detection",
                        "fine_tuned": False,
                        "last_updated": None,
                        "performance_metrics": {}
                    }
                }
            },
            "exploitation": {
                "models": {
                    "payload_generation": {
                        "model_name": "microsoft/DialoGPT-medium",
                        "task": "text_generation",
                        "description": "Intelligent payload generation",
                        "fine_tuned": False,
                        "last_updated": None,
                        "performance_metrics": {}
                    },
                    "exploit_adaptation": {
                        "model_name": "microsoft/codebert-base",
                        "task": "text_generation",
                        "description": "Adaptive exploit generation",
                        "fine_tuned": False,
                        "last_updated": None,
                        "performance_metrics": {}
                    }
                }
            },
            "reconnaissance": {
                "models": {
                    "scope_analysis": {
                        "model_name": "sentence-transformers/all-mpnet-base-v2",
                        "task": "feature_extraction",
                        "description": "Intelligent scope analysis and expansion",
                        "fine_tuned": False,
                        "last_updated": None,
                        "performance_metrics": {}
                    },
                    "subdomain_prediction": {
                        "model_name": "distilbert-base-uncased",
                        "task": "sequence_classification",
                        "description": "Subdomain existence prediction",
                        "fine_tuned": False,
                        "last_updated": None,
                        "performance_metrics": {}
                    }
                }
            }
        }

    async def download_model(self, model_name: str, task_type: str = None) -> str:
        """Download model from Hugging Face Hub"""
        self.logger.info(f"Downloading model: {model_name}")

        try:
            # Create model directory
            safe_name = model_name.replace("/", "_")
            model_dir = self.models_dir / "hf_cache" / safe_name
            model_dir.mkdir(parents=True, exist_ok=True)

            # Download model
            downloaded_path = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                snapshot_download,
                model_name,
                cache_dir=str(model_dir),
                resume_download=True
            )

            # Verify download
            if self._verify_model_integrity(downloaded_path):
                self.logger.info(f"Model {model_name} downloaded successfully")

                # Update registry
                await self._update_model_in_registry(model_name, downloaded_path, task_type)

                return downloaded_path
            else:
                raise Exception(f"Model integrity check failed for {model_name}")

        except Exception as e:
            self.logger.error(f"Error downloading model {model_name}: {e}")
            raise

    async def load_model(self, model_name: str, task_type: str = None) -> Tuple[Any, Any]:
        """Load model and tokenizer"""
        self.logger.info(f"Loading model: {model_name}")

        try:
            # Check if model exists locally
            model_path = await self._get_model_path(model_name)

            if not model_path:
                # Download if not available
                model_path = await self.download_model(model_name, task_type)

            # Load tokenizer
            tokenizer = AutoTokenizer.from_pretrained(model_path)

            # Load model based on task type
            if task_type == "sequence_classification":
                model = AutoModelForSequenceClassification.from_pretrained(model_path)
            elif task_type == "feature_extraction":
                model = AutoModel.from_pretrained(model_path)
            elif task_type == "text_generation":
                model = AutoModel.from_pretrained(model_path)
            else:
                model = AutoModel.from_pretrained(model_path)

            # Cache in active models
            self.active_models[model_name] = {
                "model": model,
                "tokenizer": tokenizer,
                "loaded_at": datetime.now(),
                "task_type": task_type
            }

            self.logger.info(f"Model {model_name} loaded successfully")
            return model, tokenizer

        except Exception as e:
            self.logger.error(f"Error loading model {model_name}: {e}")
            raise

    async def fine_tune_model(self, training_config: TrainingConfig) -> str:
        """Fine-tune a model for specific vulnerability detection tasks"""
        self.logger.info(f"Starting fine-tuning for {training_config.model_name}")

        try:
            # Load base model and tokenizer
            model, tokenizer = await self.load_model(
                training_config.model_name,
                training_config.task_type
            )

            # Prepare training data
            train_dataset, eval_dataset = await self._prepare_training_data(
                training_config, tokenizer
            )

            # Setup training arguments
            training_args = TrainingArguments(
                output_dir=training_config.output_dir,
                num_train_epochs=training_config.num_epochs,
                per_device_train_batch_size=training_config.batch_size,
                per_device_eval_batch_size=training_config.batch_size,
                learning_rate=training_config.learning_rate,
                warmup_steps=training_config.warmup_steps,
                weight_decay=training_config.weight_decay,
                logging_dir=f"{training_config.output_dir}/logs",
                logging_steps=training_config.logging_steps,
                save_steps=training_config.save_steps,
                eval_steps=training_config.eval_steps,
                evaluation_strategy="steps",
                save_total_limit=3,
                load_best_model_at_end=True,
                metric_for_best_model="eval_accuracy",
                greater_is_better=True,
                dataloader_num_workers=4,
                gradient_accumulation_steps=training_config.gradient_accumulation_steps
            )

            # Create trainer
            trainer = Trainer(
                model=model,
                args=training_args,
                train_dataset=train_dataset,
                eval_dataset=eval_dataset,
                tokenizer=tokenizer,
                compute_metrics=self._compute_metrics
            )

            # Start training
            training_result = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                trainer.train
            )

            # Save fine-tuned model
            fine_tuned_path = await self._save_fine_tuned_model(
                trainer, training_config, training_result
            )

            # Update registry
            await self._register_fine_tuned_model(training_config, fine_tuned_path)

            self.logger.info(f"Fine-tuning completed: {fine_tuned_path}")
            return fine_tuned_path

        except Exception as e:
            self.logger.error(f"Error in fine-tuning: {e}")
            raise

    async def create_custom_vulnerability_model(self, vulnerability_type: str, training_data: List[Dict]) -> str:
        """Create a custom model for specific vulnerability type"""
        self.logger.info(f"Creating custom model for {vulnerability_type}")

        try:
            # Prepare custom training configuration
            training_config = TrainingConfig(
                model_name="distilbert-base-uncased",
                task_type="sequence_classification",
                training_data_path=f"./data/custom_{vulnerability_type}_train.json",
                validation_data_path=f"./data/custom_{vulnerability_type}_val.json",
                output_dir=f"./models/custom/{vulnerability_type}",
                num_epochs=5,
                batch_size=16,
                learning_rate=2e-5,
                warmup_steps=100,
                weight_decay=0.01,
                save_steps=500,
                eval_steps=500,
                logging_steps=100,
                max_seq_length=512,
                gradient_accumulation_steps=1
            )

            # Prepare and save training data
            await self._prepare_custom_training_data(training_data, training_config)

            # Fine-tune model
            model_path = await self.fine_tune_model(training_config)

            # Register as custom model
            await self._register_custom_model(vulnerability_type, model_path)

            return model_path

        except Exception as e:
            self.logger.error(f"Error creating custom model: {e}")
            raise

    async def update_models(self) -> Dict[str, str]:
        """Update all models to latest versions"""
        self.logger.info("Checking for model updates...")

        update_results = {}

        try:
            for category, models in self.model_registry.get("vulnerability_detection", {}).get("models", {}).items():
                model_name = models["model_name"]

                # Check if update is available
                if await self._is_update_available(model_name):
                    try:
                        new_path = await self.download_model(model_name, models["task"])
                        update_results[model_name] = f"Updated to latest version: {new_path}"

                        # Update performance metrics
                        await self._benchmark_model(model_name)

                    except Exception as e:
                        update_results[model_name] = f"Update failed: {e}"
                else:
                    update_results[model_name] = "Already up to date"

            self.logger.info(f"Model update completed: {len(update_results)} models processed")
            return update_results

        except Exception as e:
            self.logger.error(f"Error in model updates: {e}")
            return {"error": str(e)}

    async def benchmark_all_models(self) -> Dict[str, Dict[str, float]]:
        """Benchmark all available models"""
        self.logger.info("Benchmarking all models...")

        benchmark_results = {}

        try:
            for category, models in self.model_registry.get("vulnerability_detection", {}).get("models", {}).items():
                model_name = models["model_name"]

                try:
                    metrics = await self._benchmark_model(model_name)
                    benchmark_results[model_name] = metrics

                    # Update registry with metrics
                    self.model_registry["vulnerability_detection"]["models"][category]["performance_metrics"] = metrics

                except Exception as e:
                    benchmark_results[model_name] = {"error": str(e)}

            # Save updated registry
            self._save_registry()

            return benchmark_results

        except Exception as e:
            self.logger.error(f"Error in benchmarking: {e}")
            return {"error": str(e)}

    async def optimize_models(self) -> Dict[str, str]:
        """Optimize models for production deployment"""
        self.logger.info("Optimizing models for production...")

        optimization_results = {}

        try:
            for model_name in self.active_models.keys():
                try:
                    # Quantize model
                    if self.config["enable_quantization"]:
                        quantized_path = await self._quantize_model(model_name)
                        optimization_results[f"{model_name}_quantized"] = quantized_path

                    # Compress model
                    if self.config["enable_model_compression"]:
                        compressed_path = await self._compress_model(model_name)
                        optimization_results[f"{model_name}_compressed"] = compressed_path

                    # ONNX conversion for faster inference
                    onnx_path = await self._convert_to_onnx(model_name)
                    optimization_results[f"{model_name}_onnx"] = onnx_path

                except Exception as e:
                    optimization_results[model_name] = f"Optimization failed: {e}"

            return optimization_results

        except Exception as e:
            self.logger.error(f"Error in model optimization: {e}")
            return {"error": str(e)}

    async def get_model_recommendations(self, task_type: str, performance_requirements: Dict[str, float]) -> List[str]:
        """Get model recommendations based on task and performance requirements"""
        self.logger.info(f"Getting model recommendations for task: {task_type}")

        try:
            recommendations = []

            # Analyze performance requirements
            required_accuracy = performance_requirements.get("accuracy", 0.8)
            max_latency_ms = performance_requirements.get("max_latency_ms", 1000)
            max_memory_mb = performance_requirements.get("max_memory_mb", 512)

            # Filter models based on requirements
            for category, models in self.model_registry.get("vulnerability_detection", {}).get("models", {}).items():
                metrics = models.get("performance_metrics", {})

                if (metrics.get("accuracy", 0) >= required_accuracy and
                    metrics.get("inference_time_ms", float('inf')) <= max_latency_ms and
                    metrics.get("memory_usage_mb", float('inf')) <= max_memory_mb):

                    recommendations.append({
                        "model_name": models["model_name"],
                        "category": category,
                        "score": self._calculate_recommendation_score(metrics, performance_requirements)
                    })

            # Sort by recommendation score
            recommendations.sort(key=lambda x: x["score"], reverse=True)

            return [r["model_name"] for r in recommendations[:5]]

        except Exception as e:
            self.logger.error(f"Error getting recommendations: {e}")
            return []

    def _verify_model_integrity(self, model_path: str) -> bool:
        """Verify model file integrity"""
        try:
            model_dir = Path(model_path)

            # Check required files exist
            required_files = ["config.json", "pytorch_model.bin"]
            for file_name in required_files:
                if not (model_dir / file_name).exists():
                    return False

            # Verify config can be loaded
            config_path = model_dir / "config.json"
            with open(config_path, 'r') as f:
                json.load(f)

            return True

        except Exception as e:
            self.logger.error(f"Model integrity check failed: {e}")
            return False

    async def _get_model_path(self, model_name: str) -> Optional[str]:
        """Get local path for model if it exists"""
        safe_name = model_name.replace("/", "_")
        model_dir = self.models_dir / "hf_cache" / safe_name

        if model_dir.exists() and self._verify_model_integrity(str(model_dir)):
            return str(model_dir)

        return None

    async def _update_model_in_registry(self, model_name: str, model_path: str, task_type: str):
        """Update model information in registry"""
        # Find model in registry and update
        for category, models in self.model_registry.get("vulnerability_detection", {}).get("models", {}).items():
            if models["model_name"] == model_name:
                models["last_updated"] = datetime.now().isoformat()
                models["model_path"] = model_path
                models["task"] = task_type
                break

        self._save_registry()

    def _save_registry(self):
        """Save model registry to disk"""
        registry_file = self.models_dir / "registry.json"
        with open(registry_file, 'w') as f:
            json.dump(self.model_registry, f, indent=2, default=str)

    async def _prepare_training_data(self, training_config: TrainingConfig, tokenizer) -> Tuple[Dataset, Dataset]:
        """Prepare training and validation datasets"""
        # Load training data
        with open(training_config.training_data_path, 'r') as f:
            train_data = json.load(f)

        with open(training_config.validation_data_path, 'r') as f:
            val_data = json.load(f)

        # Tokenize data
        def tokenize_function(examples):
            return tokenizer(
                examples["text"],
                truncation=True,
                padding=True,
                max_length=training_config.max_seq_length
            )

        train_dataset = Dataset.from_list(train_data)
        val_dataset = Dataset.from_list(val_data)

        train_dataset = train_dataset.map(tokenize_function, batched=True)
        val_dataset = val_dataset.map(tokenize_function, batched=True)

        return train_dataset, val_dataset

    def _compute_metrics(self, eval_pred):
        """Compute evaluation metrics"""
        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=1)

        # Calculate metrics
        from sklearn.metrics import accuracy_score, precision_recall_fscore_support

        accuracy = accuracy_score(labels, predictions)
        precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average='weighted')

        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1
        }

    async def _benchmark_model(self, model_name: str) -> Dict[str, float]:
        """Benchmark model performance"""
        try:
            # Load model if not already loaded
            if model_name not in self.active_models:
                await self.load_model(model_name)

            model_info = self.active_models[model_name]
            model = model_info["model"]
            tokenizer = model_info["tokenizer"]

            # Benchmark inference time
            start_time = datetime.now()
            test_input = "SELECT * FROM users WHERE username = 'admin' OR 1=1"
            inputs = tokenizer(test_input, return_tensors="pt", truncation=True, padding=True)

            with torch.no_grad():
                _ = model(**inputs)

            inference_time = (datetime.now() - start_time).total_seconds() * 1000

            # Estimate memory usage
            memory_usage = self._estimate_model_memory(model)

            return {
                "inference_time_ms": inference_time,
                "memory_usage_mb": memory_usage,
                "accuracy": 0.85,  # Placeholder - would need test dataset
                "precision": 0.82,  # Placeholder
                "recall": 0.88,     # Placeholder
                "f1_score": 0.85    # Placeholder
            }

        except Exception as e:
            self.logger.error(f"Error benchmarking model {model_name}: {e}")
            return {}

    def _estimate_model_memory(self, model) -> float:
        """Estimate model memory usage in MB"""
        param_size = 0
        for param in model.parameters():
            param_size += param.nelement() * param.element_size()

        buffer_size = 0
        for buffer in model.buffers():
            buffer_size += buffer.nelement() * buffer.element_size()

        size_mb = (param_size + buffer_size) / 1024 / 1024
        return size_mb

    def _calculate_recommendation_score(self, metrics: Dict[str, float], requirements: Dict[str, float]) -> float:
        """Calculate recommendation score based on metrics and requirements"""
        score = 0.0

        # Accuracy score (40% weight)
        if "accuracy" in metrics:
            score += 0.4 * metrics["accuracy"]

        # Latency score (30% weight)
        if "inference_time_ms" in metrics and "max_latency_ms" in requirements:
            latency_score = max(0, 1 - (metrics["inference_time_ms"] / requirements["max_latency_ms"]))
            score += 0.3 * latency_score

        # Memory score (20% weight)
        if "memory_usage_mb" in metrics and "max_memory_mb" in requirements:
            memory_score = max(0, 1 - (metrics["memory_usage_mb"] / requirements["max_memory_mb"]))
            score += 0.2 * memory_score

        # F1 score (10% weight)
        if "f1_score" in metrics:
            score += 0.1 * metrics["f1_score"]

        return score

# Export main classes
__all__ = [
    'MLModelManager',
    'ModelInfo',
    'TrainingConfig'
]