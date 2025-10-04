#!/usr/bin/env python3
"""
🤖 QuantumSentinel HuggingFace Fine-Tuning Engine
Advanced model fine-tuning with synthetic vulnerability dataset generation
"""

import asyncio
import json
import logging
import os
import random
import torch
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

# ML imports with graceful fallback
try:
    import pandas as pd
    import numpy as np
    from transformers import (
        AutoTokenizer, AutoModelForSequenceClassification,
        Trainer, TrainingArguments, EarlyStoppingCallback,
        DataCollatorWithPadding, pipeline
    )
    from datasets import Dataset, DatasetDict
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    from sklearn.model_selection import train_test_split
    import torch.nn.functional as F
    ADVANCED_ML_AVAILABLE = True
except ImportError as e:
    print(f"Advanced ML libraries not available: {e}")
    ADVANCED_ML_AVAILABLE = False

logger = logging.getLogger("QuantumSentinel.HuggingFaceTrainer")

@dataclass
class VulnerabilityPattern:
    """Vulnerability pattern for synthetic data generation"""
    vulnerability_type: str
    severity: str
    pattern_template: str
    variants: List[str]
    cwe_id: str
    owasp_category: str

@dataclass
class TrainingConfig:
    """Configuration for model training"""
    model_name: str = "microsoft/codebert-base"
    max_length: int = 512
    batch_size: int = 16
    learning_rate: float = 2e-5
    num_epochs: int = 3
    warmup_steps: int = 500
    weight_decay: float = 0.01
    evaluation_strategy: str = "epoch"
    save_steps: int = 1000
    logging_steps: int = 100

class SyntheticDatasetGenerator:
    """Generate synthetic vulnerability datasets for training"""

    def __init__(self):
        self.vulnerability_patterns = [
            VulnerabilityPattern(
                vulnerability_type="sql_injection",
                severity="high",
                pattern_template="SELECT * FROM {table} WHERE {column} = '{value}'",
                variants=[
                    "query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"",
                    "cursor.execute(f\"SELECT * FROM {table} WHERE name = '{name}'\")",
                    "db.raw(\"SELECT * FROM products WHERE category = '\" + category + \"'\")",
                    "sql = \"UPDATE users SET password = '\" + new_pass + \"' WHERE id = \" + uid",
                    "query = \"DELETE FROM logs WHERE date < '\" + date + \"'\"",
                ],
                cwe_id="CWE-89",
                owasp_category="A03_2021_Injection"
            ),
            VulnerabilityPattern(
                vulnerability_type="xss",
                severity="medium",
                pattern_template="document.innerHTML = {user_input}",
                variants=[
                    "element.innerHTML = userComment",
                    "$(\"#content\").html(userData)",
                    "document.write(request.params.message)",
                    "response.write(\"<div>\" + userInput + \"</div>\")",
                    "template = f\"<p>{user_message}</p>\"",
                ],
                cwe_id="CWE-79",
                owasp_category="A03_2021_Injection"
            ),
            VulnerabilityPattern(
                vulnerability_type="command_injection",
                severity="critical",
                pattern_template="os.system({user_command})",
                variants=[
                    "subprocess.call(user_input, shell=True)",
                    "system(\"ping \" + target_host)",
                    "exec(\"ls \" + directory)",
                    "os.popen(command_string).read()",
                    "Runtime.getRuntime().exec(userCommand)",
                ],
                cwe_id="CWE-78",
                owasp_category="A03_2021_Injection"
            ),
            VulnerabilityPattern(
                vulnerability_type="hardcoded_credentials",
                severity="high",
                pattern_template="password = '{password}'",
                variants=[
                    "API_KEY = \"sk-1234567890abcdef\"",
                    "database_password = \"admin123\"",
                    "jwt_secret = \"my-super-secret-key\"",
                    "private_key = \"-----BEGIN RSA PRIVATE KEY-----\"",
                    "oauth_token = \"ghp_1234567890abcdef\"",
                ],
                cwe_id="CWE-798",
                owasp_category="A07_2021_Identification_and_Authentication_Failures"
            ),
            VulnerabilityPattern(
                vulnerability_type="path_traversal",
                severity="medium",
                pattern_template="open({filename})",
                variants=[
                    "with open(user_file, 'r') as f:",
                    "File.read(request.params.path)",
                    "fs.readFile(filePath, callback)",
                    "include($_GET['page'])",
                    "readFile(\"./uploads/\" + filename)",
                ],
                cwe_id="CWE-22",
                owasp_category="A01_2021_Broken_Access_Control"
            ),
            VulnerabilityPattern(
                vulnerability_type="insecure_crypto",
                severity="medium",
                pattern_template="md5({data})",
                variants=[
                    "hashlib.md5(password.encode())",
                    "SHA1.digest(data)",
                    "crypto.createHash('md5').update(text)",
                    "MessageDigest.getInstance(\"MD5\")",
                    "hash = md5(user_input)",
                ],
                cwe_id="CWE-327",
                owasp_category="A02_2021_Cryptographic_Failures"
            ),
            VulnerabilityPattern(
                vulnerability_type="unsafe_deserialization",
                severity="critical",
                pattern_template="pickle.loads({data})",
                variants=[
                    "pickle.loads(request.data)",
                    "yaml.load(user_input)",
                    "json.loads(untrusted_data, object_hook=custom_hook)",
                    "ObjectInputStream.readObject()",
                    "unserialize($_POST['data'])",
                ],
                cwe_id="CWE-502",
                owasp_category="A08_2021_Software_and_Data_Integrity_Failures"
            ),
            VulnerabilityPattern(
                vulnerability_type="weak_authentication",
                severity="medium",
                pattern_template="if password == '{weak_password}':",
                variants=[
                    "if user_pass == \"password123\":",
                    "authenticate(username, \"\")",
                    "login_required = False",
                    "if len(password) < 6:",
                    "session['authenticated'] = True  # No password check",
                ],
                cwe_id="CWE-287",
                owasp_category="A07_2021_Identification_and_Authentication_Failures"
            ),
        ]

        # Safe code patterns for negative examples
        self.safe_patterns = [
            "password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
            "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
            "html.escape(user_input)",
            "subprocess.run(command, shell=False, check=True)",
            "with open(os.path.join(SAFE_DIR, filename), 'r') as f:",
            "if user.is_authenticated and user.has_permission('admin'):",
            "token = secrets.token_urlsafe(32)",
            "hashlib.sha256(data.encode()).hexdigest()",
            "json.loads(data, strict=True)",
            "validate_input(user_data) and sanitize_output(response)",
        ]

    def generate_synthetic_dataset(self, num_samples: int = 1000) -> List[Dict[str, Any]]:
        """Generate synthetic vulnerability dataset"""
        dataset = []

        # Generate vulnerable code samples
        vuln_samples = int(num_samples * 0.7)  # 70% vulnerable
        for _ in range(vuln_samples):
            pattern = random.choice(self.vulnerability_patterns)
            code_sample = random.choice(pattern.variants)

            # Add some noise and variations
            code_sample = self._add_code_variations(code_sample)

            dataset.append({
                'code': code_sample,
                'label': 1,  # Vulnerable
                'vulnerability_type': pattern.vulnerability_type,
                'severity': pattern.severity,
                'cwe_id': pattern.cwe_id,
                'owasp_category': pattern.owasp_category,
            })

        # Generate safe code samples
        safe_samples = num_samples - vuln_samples
        for _ in range(safe_samples):
            code_sample = random.choice(self.safe_patterns)
            code_sample = self._add_code_variations(code_sample)

            dataset.append({
                'code': code_sample,
                'label': 0,  # Safe
                'vulnerability_type': 'safe',
                'severity': 'none',
                'cwe_id': None,
                'owasp_category': None,
            })

        # Shuffle dataset
        random.shuffle(dataset)
        return dataset

    def _add_code_variations(self, code: str) -> str:
        """Add realistic variations to code samples"""
        variations = [
            lambda x: x.replace("'", '"'),  # Quote style
            lambda x: x.replace('  ', '    '),  # Indentation
            lambda x: x + '  # TODO: Fix this',  # Comments
            lambda x: x.replace('user_', 'usr_'),  # Variable naming
            lambda x: x.replace('data', 'input_data'),  # Variable expansion
        ]

        # Apply random variations
        for _ in range(random.randint(0, 2)):
            variation = random.choice(variations)
            code = variation(code)

        return code

class HuggingFaceTrainer:
    """Advanced HuggingFace model fine-tuning for vulnerability detection"""

    def __init__(self, config: Optional[TrainingConfig] = None):
        self.config = config or TrainingConfig()
        self.model = None
        self.tokenizer = None
        self.dataset_generator = SyntheticDatasetGenerator()
        self.model_dir = Path("models/vulnerability_detector")
        self.model_dir.mkdir(parents=True, exist_ok=True)

    async def initialize(self):
        """Initialize the trainer"""
        if not ADVANCED_ML_AVAILABLE:
            raise RuntimeError("Advanced ML libraries not available")

        logger.info(f"Initializing HuggingFace trainer with model: {self.config.model_name}")

        # Load tokenizer and model
        self.tokenizer = AutoTokenizer.from_pretrained(self.config.model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(
            self.config.model_name,
            num_labels=2,  # Binary classification: vulnerable vs safe
            problem_type="single_label_classification"
        )

        # Add padding token if not present
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        logger.info("✅ HuggingFace trainer initialized")

    async def prepare_dataset(self, num_samples: int = 2000) -> DatasetDict:
        """Prepare training and validation datasets"""
        logger.info(f"Generating synthetic dataset with {num_samples} samples...")

        # Generate synthetic data
        synthetic_data = self.dataset_generator.generate_synthetic_dataset(num_samples)

        # Convert to DataFrame for easier manipulation
        df = pd.DataFrame(synthetic_data)

        # Split into train/validation/test
        train_df, temp_df = train_test_split(df, test_size=0.3, random_state=42, stratify=df['label'])
        val_df, test_df = train_test_split(temp_df, test_size=0.5, random_state=42, stratify=temp_df['label'])

        # Tokenize datasets
        def tokenize_function(examples):
            return self.tokenizer(
                examples['code'],
                truncation=True,
                padding=True,
                max_length=self.config.max_length,
                return_tensors="pt"
            )

        # Convert to HuggingFace datasets
        train_dataset = Dataset.from_pandas(train_df)
        val_dataset = Dataset.from_pandas(val_df)
        test_dataset = Dataset.from_pandas(test_df)

        # Apply tokenization
        train_dataset = train_dataset.map(tokenize_function, batched=True)
        val_dataset = val_dataset.map(tokenize_function, batched=True)
        test_dataset = test_dataset.map(tokenize_function, batched=True)

        # Set format for PyTorch
        train_dataset.set_format(type='torch', columns=['input_ids', 'attention_mask', 'label'])
        val_dataset.set_format(type='torch', columns=['input_ids', 'attention_mask', 'label'])
        test_dataset.set_format(type='torch', columns=['input_ids', 'attention_mask', 'label'])

        dataset_dict = DatasetDict({
            'train': train_dataset,
            'validation': val_dataset,
            'test': test_dataset
        })

        logger.info(f"✅ Dataset prepared: {len(train_dataset)} train, {len(val_dataset)} val, {len(test_dataset)} test")
        return dataset_dict

    def compute_metrics(self, eval_pred):
        """Compute metrics for evaluation"""
        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=1)

        precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average='weighted')
        accuracy = accuracy_score(labels, predictions)

        return {
            'accuracy': accuracy,
            'f1': f1,
            'precision': precision,
            'recall': recall
        }

    async def fine_tune_model(self, dataset: DatasetDict) -> Dict[str, Any]:
        """Fine-tune the model on vulnerability detection"""
        logger.info("Starting model fine-tuning...")

        # Set up training arguments
        training_args = TrainingArguments(
            output_dir=str(self.model_dir / "checkpoints"),
            evaluation_strategy=self.config.evaluation_strategy,
            save_strategy="epoch",
            learning_rate=self.config.learning_rate,
            per_device_train_batch_size=self.config.batch_size,
            per_device_eval_batch_size=self.config.batch_size,
            num_train_epochs=self.config.num_epochs,
            weight_decay=self.config.weight_decay,
            warmup_steps=self.config.warmup_steps,
            logging_steps=self.config.logging_steps,
            save_steps=self.config.save_steps,
            load_best_model_at_end=True,
            metric_for_best_model="f1",
            greater_is_better=True,
            dataloader_pin_memory=False,
            report_to=None,  # Disable wandb/tensorboard
        )

        # Data collator
        data_collator = DataCollatorWithPadding(tokenizer=self.tokenizer)

        # Create trainer
        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=dataset['train'],
            eval_dataset=dataset['validation'],
            tokenizer=self.tokenizer,
            data_collator=data_collator,
            compute_metrics=self.compute_metrics,
            callbacks=[EarlyStoppingCallback(early_stopping_patience=2)]
        )

        # Start training
        start_time = datetime.now()
        train_result = trainer.train()
        training_time = datetime.now() - start_time

        # Evaluate on test set
        test_results = trainer.evaluate(dataset['test'])

        # Save the fine-tuned model
        model_path = self.model_dir / "fine_tuned"
        trainer.save_model(str(model_path))
        self.tokenizer.save_pretrained(str(model_path))

        # Save training metadata
        metadata = {
            'model_name': self.config.model_name,
            'training_samples': len(dataset['train']),
            'validation_samples': len(dataset['validation']),
            'test_samples': len(dataset['test']),
            'training_time': str(training_time),
            'train_loss': train_result.training_loss,
            'test_accuracy': test_results['eval_accuracy'],
            'test_f1': test_results['eval_f1'],
            'test_precision': test_results['eval_precision'],
            'test_recall': test_results['eval_recall'],
            'config': self.config.__dict__,
            'timestamp': datetime.now().isoformat()
        }

        with open(self.model_dir / "training_metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"✅ Model fine-tuning completed in {training_time}")
        logger.info(f"📊 Test Results - Accuracy: {test_results['eval_accuracy']:.4f}, F1: {test_results['eval_f1']:.4f}")

        return metadata

    async def load_fine_tuned_model(self) -> Optional[Any]:
        """Load the fine-tuned model for inference"""
        model_path = self.model_dir / "fine_tuned"

        if not model_path.exists():
            logger.warning("No fine-tuned model found")
            return None

        try:
            # Load the fine-tuned model
            classifier = pipeline(
                "text-classification",
                model=str(model_path),
                tokenizer=str(model_path),
                device=0 if torch.cuda.is_available() else -1
            )

            logger.info("✅ Fine-tuned model loaded for inference")
            return classifier

        except Exception as e:
            logger.error(f"Failed to load fine-tuned model: {e}")
            return None

    async def analyze_code(self, code: str, classifier=None) -> Dict[str, Any]:
        """Analyze code using the fine-tuned model"""
        if classifier is None:
            classifier = await self.load_fine_tuned_model()

        if classifier is None:
            return {
                'vulnerability_detected': False,
                'confidence': 0.0,
                'error': 'No trained model available'
            }

        try:
            # Get prediction
            result = classifier(code)

            # Parse result (assuming binary classification)
            is_vulnerable = result[0]['label'] == 'LABEL_1'  # 1 = vulnerable
            confidence = result[0]['score']

            return {
                'vulnerability_detected': is_vulnerable,
                'confidence': confidence,
                'prediction': result[0],
                'model_type': 'fine_tuned_transformer'
            }

        except Exception as e:
            logger.error(f"Error during code analysis: {e}")
            return {
                'vulnerability_detected': False,
                'confidence': 0.0,
                'error': str(e)
            }

    async def generate_training_report(self) -> Dict[str, Any]:
        """Generate comprehensive training report"""
        metadata_file = self.model_dir / "training_metadata.json"

        if not metadata_file.exists():
            return {'error': 'No training metadata found'}

        with open(metadata_file, 'r') as f:
            metadata = json.load(f)

        # Add model file information
        model_path = self.model_dir / "fine_tuned"
        model_size = 0
        if model_path.exists():
            for file_path in model_path.rglob('*'):
                if file_path.is_file():
                    model_size += file_path.stat().st_size

        report = {
            'training_summary': metadata,
            'model_info': {
                'model_path': str(model_path),
                'model_size_mb': round(model_size / (1024 * 1024), 2),
                'files_present': list(model_path.glob('*')) if model_path.exists() else []
            },
            'performance_metrics': {
                'accuracy': metadata.get('test_accuracy', 0),
                'f1_score': metadata.get('test_f1', 0),
                'precision': metadata.get('test_precision', 0),
                'recall': metadata.get('test_recall', 0)
            },
            'dataset_info': {
                'total_samples': metadata.get('training_samples', 0) + metadata.get('validation_samples', 0) + metadata.get('test_samples', 0),
                'train_split': metadata.get('training_samples', 0),
                'validation_split': metadata.get('validation_samples', 0),
                'test_split': metadata.get('test_samples', 0)
            }
        }

        return report

# Main training workflow
async def train_vulnerability_model(
    num_samples: int = 2000,
    model_name: str = "microsoft/codebert-base",
    epochs: int = 3
) -> Dict[str, Any]:
    """Main workflow for training vulnerability detection model"""

    config = TrainingConfig(
        model_name=model_name,
        num_epochs=epochs,
        batch_size=16,
        learning_rate=2e-5
    )

    trainer = HuggingFaceTrainer(config)

    try:
        # Initialize trainer
        await trainer.initialize()

        # Prepare dataset
        dataset = await trainer.prepare_dataset(num_samples)

        # Fine-tune model
        results = await trainer.fine_tune_model(dataset)

        # Generate report
        report = await trainer.generate_training_report()

        return {
            'success': True,
            'training_results': results,
            'report': report
        }

    except Exception as e:
        logger.error(f"Training workflow failed: {e}")
        return {
            'success': False,
            'error': str(e)
        }

if __name__ == "__main__":
    # Example usage
    async def main():
        result = await train_vulnerability_model(
            num_samples=1000,
            model_name="microsoft/codebert-base",
            epochs=2
        )
        print(json.dumps(result, indent=2))

    asyncio.run(main())