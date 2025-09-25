"""
Vulnerability Dataset Integration for Training and Validation
Integrates HuggingFace datasets for continuous model improvement
"""
import json
import logging
import asyncio
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Generator
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib
import aiohttp
from pathlib import Path

# Optional dataset imports
try:
    from datasets import load_dataset, Dataset
    import requests
    DATASETS_AVAILABLE = True
except ImportError:
    DATASETS_AVAILABLE = False
    logging.warning("Hugging Face datasets not available - using mock implementations")

@dataclass
class DatasetInfo:
    """Dataset information structure"""
    dataset_id: str
    name: str
    description: str
    size: int
    features: List[str]
    use_cases: List[str]
    loaded_at: datetime
    version: str
    sample_count: int

@dataclass
class TrainingBatch:
    """Training batch structure"""
    batch_id: str
    dataset_source: str
    features: np.ndarray
    labels: np.ndarray
    metadata: Dict[str, Any]
    quality_score: float

class VulnerabilityDatasetIntegration:
    """
    Vulnerability Dataset Integration System

    Integrates datasets:
    - CyberNative/Code_Vulnerability_Security_DPO
    - atul10/recreated_reverse_engineering_code_dataset_O1_x86_O1
    - Custom vulnerability datasets
    - Real-time learning data from assessments
    """

    def __init__(self, cache_dir: str = "dataset_cache"):
        self.logger = logging.getLogger(__name__)
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

        self.datasets = {}
        self.dataset_configs = {}
        self.training_batches = {}
        self.quality_metrics = {}

        self._initialize_dataset_configs()

    def _initialize_dataset_configs(self):
        """Initialize dataset configurations"""
        try:
            self.dataset_configs = {
                'vulnerability_dpo': {
                    'dataset_id': 'CyberNative/Code_Vulnerability_Security_DPO',
                    'name': 'Code Vulnerability Security Dataset with DPO',
                    'description': 'Comprehensive dataset for vulnerability detection with direct preference optimization',
                    'features': ['code', 'vulnerability_type', 'severity', 'cwe_id', 'description'],
                    'use_cases': ['vulnerability_detection', 'secure_coding', 'code_analysis', 'severity_prediction'],
                    'preprocessing_required': True,
                    'sampling_strategy': 'balanced'
                },
                'cve_multiturn_2025': {
                    'dataset_id': 'Trendyol/All-CVE-Chat-MultiTurn-1999-2025-Dataset',
                    'name': 'CVE Chat Multi-Turn Dataset 2025',
                    'description': '300k CVE records from 1999-2025 in conversational format for AI training',
                    'features': ['cve_id', 'conversation', 'severity', 'description', 'solution'],
                    'use_cases': ['vulnerability_chat', 'cve_analysis', 'threat_intelligence', 'security_qa'],
                    'preprocessing_required': True,
                    'sampling_strategy': 'temporal'
                },
                'cve_records_training': {
                    'dataset_id': 'AlicanKiraz0/All-CVE-Records-Training-Dataset',
                    'name': 'All CVE Records Training Dataset',
                    'description': 'Comprehensive CVE records dataset for training vulnerability models',
                    'features': ['cve_id', 'cvss_score', 'vulnerability_type', 'affected_products'],
                    'use_cases': ['vulnerability_classification', 'risk_assessment', 'threat_modeling'],
                    'preprocessing_required': True,
                    'sampling_strategy': 'severity_based'
                },
                'cve_cwe_dataset': {
                    'dataset_id': 'stasvinokur/cve-and-cwe-dataset-1999-2025',
                    'name': 'CVE and CWE Dataset 1999-2025',
                    'description': 'Combined CVE and CWE mapping dataset with temporal coverage',
                    'features': ['cve_id', 'cwe_id', 'category', 'weakness_type', 'timeline'],
                    'use_cases': ['weakness_classification', 'cve_cwe_mapping', 'vulnerability_taxonomy'],
                    'preprocessing_required': True,
                    'sampling_strategy': 'cwe_balanced'
                },
                'cybersecurity_corpus': {
                    'dataset_id': 'zeroshot/cybersecurity-corpus',
                    'name': 'Cybersecurity Corpus',
                    'description': 'General cybersecurity knowledge corpus for comprehensive training',
                    'features': ['topic', 'content', 'category', 'expertise_level'],
                    'use_cases': ['knowledge_base', 'general_security', 'educational_content'],
                    'preprocessing_required': True,
                    'sampling_strategy': 'topic_balanced'
                },
                'security_breaches': {
                    'dataset_id': 'schooly/Cyber-Security-Breaches',
                    'name': 'Cyber Security Breaches Dataset',
                    'description': 'Real-world security breach incidents and case studies',
                    'features': ['incident_type', 'impact', 'timeline', 'lessons_learned'],
                    'use_cases': ['incident_response', 'threat_modeling', 'case_studies'],
                    'preprocessing_required': True,
                    'sampling_strategy': 'incident_type'
                },
                'reverse_engineering': {
                    'dataset_id': 'atul10/recreated_reverse_engineering_code_dataset_O1_x86_O1',
                    'name': 'Reverse Engineering Code Dataset x86',
                    'description': 'Assembly and binary analysis dataset for reverse engineering',
                    'features': ['assembly_code', 'binary_data', 'function_name', 'architecture'],
                    'use_cases': ['binary_analysis', 'malware_detection', 'assembly_understanding'],
                    'preprocessing_required': True,
                    'sampling_strategy': 'stratified'
                },
                'custom_vulnerabilities': {
                    'dataset_id': 'custom/vulnerability_findings',
                    'name': 'Custom Vulnerability Findings',
                    'description': 'Real-time vulnerability findings from assessments',
                    'features': ['code_snippet', 'vulnerability_class', 'confidence', 'tool_detected'],
                    'use_cases': ['model_fine_tuning', 'pattern_recognition', 'confidence_calibration'],
                    'preprocessing_required': False,
                    'sampling_strategy': 'time_based'
                },
                'api_security_patterns': {
                    'dataset_id': 'custom/api_security_patterns',
                    'name': 'API Security Patterns',
                    'description': 'API key exposure and security patterns from KeyHacks integration',
                    'features': ['api_key_pattern', 'service_type', 'validation_result', 'context'],
                    'use_cases': ['api_security', 'key_detection', 'false_positive_reduction'],
                    'preprocessing_required': False,
                    'sampling_strategy': 'importance_sampling'
                }
            }

            self.logger.info("📊 Dataset configurations initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize dataset configs: {e}")

    async def load_datasets(self, dataset_names: List[str] = None) -> Dict[str, DatasetInfo]:
        """Load specified datasets"""
        try:
            dataset_names = dataset_names or list(self.dataset_configs.keys())
            loaded_datasets = {}

            self.logger.info(f"📥 Loading {len(dataset_names)} datasets")

            for dataset_name in dataset_names:
                if dataset_name not in self.dataset_configs:
                    self.logger.warning(f"Unknown dataset: {dataset_name}")
                    continue

                config = self.dataset_configs[dataset_name]
                self.logger.info(f"Loading dataset: {config['name']}")

                try:
                    if dataset_name.startswith('custom'):
                        # Load custom dataset
                        dataset_info = await self._load_custom_dataset(dataset_name, config)
                    else:
                        # Load HuggingFace dataset
                        dataset_info = await self._load_huggingface_dataset(dataset_name, config)

                    if dataset_info:
                        loaded_datasets[dataset_name] = dataset_info
                        self.datasets[dataset_name] = dataset_info
                        self.logger.info(f"✅ Loaded {dataset_name}: {dataset_info.sample_count} samples")

                except Exception as e:
                    self.logger.error(f"Failed to load dataset {dataset_name}: {e}")

            return loaded_datasets

        except Exception as e:
            self.logger.error(f"Failed to load datasets: {e}")
            return {}

    async def _load_huggingface_dataset(self, dataset_name: str, config: Dict[str, Any]) -> Optional[DatasetInfo]:
        """Load dataset from HuggingFace"""
        try:
            if not DATASETS_AVAILABLE:
                # Mock dataset for demo
                return await self._create_mock_dataset(dataset_name, config)

            dataset_id = config['dataset_id']

            # Load dataset with caching
            try:
                dataset = load_dataset(dataset_id, cache_dir=str(self.cache_dir))

                # Get the train split or first available split
                if 'train' in dataset:
                    data = dataset['train']
                else:
                    # Take first available split
                    split_name = list(dataset.keys())[0]
                    data = dataset[split_name]

                # Preprocess if required
                if config.get('preprocessing_required', False):
                    data = await self._preprocess_dataset(data, dataset_name)

                dataset_info = DatasetInfo(
                    dataset_id=dataset_id,
                    name=config['name'],
                    description=config['description'],
                    size=len(data),
                    features=config['features'],
                    use_cases=config['use_cases'],
                    loaded_at=datetime.now(),
                    version="1.0",
                    sample_count=len(data)
                )

                # Store processed data
                self.datasets[f"{dataset_name}_data"] = data

                return dataset_info

            except Exception as e:
                self.logger.error(f"Failed to load HuggingFace dataset {dataset_id}: {e}")
                return await self._create_mock_dataset(dataset_name, config)

        except Exception as e:
            self.logger.error(f"Failed to load HuggingFace dataset {dataset_name}: {e}")
            return None

    async def _load_custom_dataset(self, dataset_name: str, config: Dict[str, Any]) -> Optional[DatasetInfo]:
        """Load custom dataset from local files or generated data"""
        try:
            if dataset_name == 'custom_vulnerabilities':
                return await self._create_vulnerability_dataset(config)
            elif dataset_name == 'api_security_patterns':
                return await self._create_api_security_dataset(config)
            else:
                return await self._create_mock_dataset(dataset_name, config)

        except Exception as e:
            self.logger.error(f"Failed to load custom dataset {dataset_name}: {e}")
            return None

    async def _create_vulnerability_dataset(self, config: Dict[str, Any]) -> DatasetInfo:
        """Create vulnerability dataset from assessment findings"""
        try:
            # Generate synthetic vulnerability data for training
            vulnerability_samples = []

            # SQL Injection samples
            sql_samples = [
                {
                    'code': "SELECT * FROM users WHERE id = " + "'" + user_id + "'",
                    'vulnerability_type': 'sql_injection',
                    'severity': 'high',
                    'cwe_id': 'CWE-89',
                    'description': 'Direct SQL injection vulnerability'
                },
                {
                    'code': "query = f'SELECT * FROM products WHERE name = {product_name}'",
                    'vulnerability_type': 'sql_injection',
                    'severity': 'high',
                    'cwe_id': 'CWE-89',
                    'description': 'F-string SQL injection'
                }
            ]

            # XSS samples
            xss_samples = [
                {
                    'code': "document.getElementById('output').innerHTML = user_input;",
                    'vulnerability_type': 'xss',
                    'severity': 'medium',
                    'cwe_id': 'CWE-79',
                    'description': 'Direct DOM XSS vulnerability'
                },
                {
                    'code': "echo '<div>' . $_GET['message'] . '</div>';",
                    'vulnerability_type': 'xss',
                    'severity': 'medium',
                    'cwe_id': 'CWE-79',
                    'description': 'Reflected XSS vulnerability'
                }
            ]

            # Buffer overflow samples
            buffer_samples = [
                {
                    'code': "char buffer[10]; strcpy(buffer, user_input);",
                    'vulnerability_type': 'buffer_overflow',
                    'severity': 'critical',
                    'cwe_id': 'CWE-120',
                    'description': 'Stack buffer overflow'
                }
            ]

            # Combine all samples
            vulnerability_samples.extend(sql_samples)
            vulnerability_samples.extend(xss_samples)
            vulnerability_samples.extend(buffer_samples)

            # Add secure code samples for balance
            secure_samples = [
                {
                    'code': "stmt = db.prepare('SELECT * FROM users WHERE id = ?'); stmt.execute([user_id]);",
                    'vulnerability_type': 'secure',
                    'severity': 'none',
                    'cwe_id': 'N/A',
                    'description': 'Parameterized query - secure'
                },
                {
                    'code': "output.textContent = user_input;",
                    'vulnerability_type': 'secure',
                    'severity': 'none',
                    'cwe_id': 'N/A',
                    'description': 'Safe DOM manipulation'
                }
            ]

            vulnerability_samples.extend(secure_samples)

            # Store in custom format
            self.datasets[f"custom_vulnerabilities_data"] = vulnerability_samples

            return DatasetInfo(
                dataset_id=config['dataset_id'],
                name=config['name'],
                description=config['description'],
                size=len(vulnerability_samples),
                features=config['features'],
                use_cases=config['use_cases'],
                loaded_at=datetime.now(),
                version="1.0",
                sample_count=len(vulnerability_samples)
            )

        except Exception as e:
            self.logger.error(f"Failed to create vulnerability dataset: {e}")
            raise

    async def _create_api_security_dataset(self, config: Dict[str, Any]) -> DatasetInfo:
        """Create API security pattern dataset"""
        try:
            api_samples = [
                {
                    'api_key_pattern': 'AKIA[A-Z0-9]{16}',
                    'service_type': 'aws',
                    'validation_result': 'valid',
                    'context': 'configuration_file'
                },
                {
                    'api_key_pattern': 'AIza[A-Za-z0-9_-]{35}',
                    'service_type': 'google',
                    'validation_result': 'invalid',
                    'context': 'source_code'
                },
                {
                    'api_key_pattern': 'gh[pousr]_[A-Za-z0-9]{36}',
                    'service_type': 'github',
                    'validation_result': 'valid',
                    'context': 'environment_variable'
                },
                {
                    'api_key_pattern': 'sk_live_[0-9a-zA-Z]{24,}',
                    'service_type': 'stripe',
                    'validation_result': 'valid',
                    'context': 'configuration_file'
                },
                {
                    'api_key_pattern': 'xoxb-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}',
                    'service_type': 'slack',
                    'validation_result': 'invalid',
                    'context': 'documentation'
                }
            ]

            self.datasets[f"api_security_patterns_data"] = api_samples

            return DatasetInfo(
                dataset_id=config['dataset_id'],
                name=config['name'],
                description=config['description'],
                size=len(api_samples),
                features=config['features'],
                use_cases=config['use_cases'],
                loaded_at=datetime.now(),
                version="1.0",
                sample_count=len(api_samples)
            )

        except Exception as e:
            self.logger.error(f"Failed to create API security dataset: {e}")
            raise

    async def _create_mock_dataset(self, dataset_name: str, config: Dict[str, Any]) -> DatasetInfo:
        """Create mock dataset when real datasets are unavailable"""
        try:
            # Generate mock data based on dataset type
            sample_count = 1000

            mock_data = []
            for i in range(sample_count):
                if 'vulnerability' in dataset_name:
                    sample = {
                        'code': f"function example_{i}() {{ var x = input_{i}; }}",
                        'vulnerability_type': ['xss', 'sql_injection', 'secure'][i % 3],
                        'severity': ['low', 'medium', 'high'][i % 3],
                        'cwe_id': f"CWE-{79 + (i % 10)}",
                        'description': f"Mock vulnerability description {i}"
                    }
                elif 'reverse_engineering' in dataset_name:
                    sample = {
                        'assembly_code': f"mov eax, {i}\npush eax\ncall function_{i}",
                        'binary_data': f"\\x48\\x8b\\x{i:02x}",
                        'function_name': f"function_{i}",
                        'architecture': 'x86_64'
                    }
                else:
                    sample = {f"feature_{j}": f"value_{i}_{j}" for j in range(5)}

                mock_data.append(sample)

            self.datasets[f"{dataset_name}_data"] = mock_data

            return DatasetInfo(
                dataset_id=config['dataset_id'],
                name=f"Mock {config['name']}",
                description=f"Mock dataset for {config['description']}",
                size=sample_count,
                features=config['features'],
                use_cases=config['use_cases'],
                loaded_at=datetime.now(),
                version="mock_1.0",
                sample_count=sample_count
            )

        except Exception as e:
            self.logger.error(f"Failed to create mock dataset: {e}")
            raise

    async def _preprocess_dataset(self, dataset: Any, dataset_name: str) -> Any:
        """Preprocess dataset for training"""
        try:
            self.logger.info(f"🔄 Preprocessing dataset: {dataset_name}")

            # For HuggingFace datasets, apply preprocessing transformations
            if hasattr(dataset, 'map'):
                if 'vulnerability' in dataset_name:
                    # Vulnerability-specific preprocessing
                    dataset = dataset.map(self._preprocess_vulnerability_sample)
                elif 'reverse_engineering' in dataset_name:
                    # Binary analysis preprocessing
                    dataset = dataset.map(self._preprocess_binary_sample)

                # Filter out invalid samples
                dataset = dataset.filter(lambda x: self._is_valid_sample(x, dataset_name))

            return dataset

        except Exception as e:
            self.logger.error(f"Failed to preprocess dataset {dataset_name}: {e}")
            return dataset

    def _preprocess_vulnerability_sample(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """Preprocess vulnerability sample"""
        try:
            # Clean code sample
            if 'code' in sample:
                sample['code'] = sample['code'].strip()
                sample['code_length'] = len(sample['code'])

            # Normalize vulnerability type
            if 'vulnerability_type' in sample:
                sample['vulnerability_type'] = sample['vulnerability_type'].lower().strip()

            # Add severity score
            severity_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'none': 0}
            if 'severity' in sample:
                sample['severity_score'] = severity_map.get(sample['severity'].lower(), 0)

            return sample

        except Exception as e:
            self.logger.error(f"Failed to preprocess vulnerability sample: {e}")
            return sample

    def _preprocess_binary_sample(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """Preprocess binary analysis sample"""
        try:
            # Clean assembly code
            if 'assembly_code' in sample:
                sample['assembly_code'] = sample['assembly_code'].strip()
                sample['instruction_count'] = len(sample['assembly_code'].split('\n'))

            # Extract binary features
            if 'binary_data' in sample:
                sample['binary_length'] = len(sample['binary_data'])

            return sample

        except Exception as e:
            self.logger.error(f"Failed to preprocess binary sample: {e}")
            return sample

    def _is_valid_sample(self, sample: Dict[str, Any], dataset_name: str) -> bool:
        """Check if sample is valid for training"""
        try:
            if 'vulnerability' in dataset_name:
                return (
                    'code' in sample and
                    len(sample['code'].strip()) > 10 and
                    'vulnerability_type' in sample
                )
            elif 'reverse_engineering' in dataset_name:
                return (
                    'assembly_code' in sample and
                    len(sample['assembly_code'].strip()) > 5
                )
            else:
                return True

        except Exception as e:
            self.logger.error(f"Failed to validate sample: {e}")
            return False

    async def create_training_batches(self, dataset_names: List[str],
                                    batch_size: int = 32,
                                    use_case: str = 'vulnerability_detection') -> List[TrainingBatch]:
        """Create training batches from loaded datasets"""
        try:
            self.logger.info(f"📦 Creating training batches for use case: {use_case}")

            all_batches = []

            for dataset_name in dataset_names:
                if dataset_name not in self.datasets:
                    self.logger.warning(f"Dataset {dataset_name} not loaded")
                    continue

                # Get dataset data
                dataset_key = f"{dataset_name}_data"
                if dataset_key not in self.datasets:
                    self.logger.warning(f"Dataset data {dataset_key} not found")
                    continue

                data = self.datasets[dataset_key]

                # Create batches for this dataset
                batches = await self._create_dataset_batches(
                    data, dataset_name, batch_size, use_case
                )

                all_batches.extend(batches)

            # Shuffle batches
            np.random.shuffle(all_batches)

            self.logger.info(f"📦 Created {len(all_batches)} training batches")
            return all_batches

        except Exception as e:
            self.logger.error(f"Failed to create training batches: {e}")
            return []

    async def _create_dataset_batches(self, data: List[Dict[str, Any]], dataset_name: str,
                                    batch_size: int, use_case: str) -> List[TrainingBatch]:
        """Create batches from a single dataset"""
        try:
            batches = []

            # Convert to features and labels based on use case
            features, labels = await self._extract_features_labels(data, use_case)

            # Create batches
            for i in range(0, len(features), batch_size):
                batch_features = features[i:i + batch_size]
                batch_labels = labels[i:i + batch_size]

                if len(batch_features) == 0:
                    continue

                # Calculate quality score
                quality_score = await self._calculate_batch_quality(batch_features, batch_labels)

                batch = TrainingBatch(
                    batch_id=f"batch_{dataset_name}_{i//batch_size}_{datetime.now().timestamp()}",
                    dataset_source=dataset_name,
                    features=np.array(batch_features),
                    labels=np.array(batch_labels),
                    metadata={
                        'batch_index': i // batch_size,
                        'use_case': use_case,
                        'original_size': len(batch_features),
                        'dataset_source': dataset_name
                    },
                    quality_score=quality_score
                )

                batches.append(batch)

            return batches

        except Exception as e:
            self.logger.error(f"Failed to create batches for dataset {dataset_name}: {e}")
            return []

    async def _extract_features_labels(self, data: List[Dict[str, Any]],
                                     use_case: str) -> Tuple[List[List[float]], List[Any]]:
        """Extract features and labels from data based on use case"""
        try:
            features = []
            labels = []

            for sample in data:
                if use_case == 'vulnerability_detection':
                    # Extract vulnerability detection features
                    feature_vector = await self._extract_vulnerability_features(sample)
                    label = 1 if sample.get('vulnerability_type', 'secure') != 'secure' else 0

                elif use_case == 'severity_prediction':
                    # Extract severity prediction features
                    feature_vector = await self._extract_vulnerability_features(sample)
                    severity_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'none': 0}
                    label = severity_map.get(sample.get('severity', 'none').lower(), 0)

                elif use_case == 'binary_analysis':
                    # Extract binary analysis features
                    feature_vector = await self._extract_binary_features(sample)
                    label = sample.get('is_malicious', 0)

                elif use_case == 'api_security':
                    # Extract API security features
                    feature_vector = await self._extract_api_features(sample)
                    label = 1 if sample.get('validation_result') == 'valid' else 0

                else:
                    # Default feature extraction
                    feature_vector = [1.0] * 10  # Dummy features
                    label = 0

                if feature_vector and len(feature_vector) > 0:
                    features.append(feature_vector)
                    labels.append(label)

            return features, labels

        except Exception as e:
            self.logger.error(f"Failed to extract features and labels: {e}")
            return [], []

    async def _extract_vulnerability_features(self, sample: Dict[str, Any]) -> List[float]:
        """Extract features for vulnerability detection"""
        try:
            features = []

            # Code-based features
            code = sample.get('code', '')
            features.extend([
                len(code),  # Code length
                code.count('SELECT'),  # SQL keywords
                code.count('INSERT'),
                code.count('UPDATE'),
                code.count('DELETE'),
                code.count('innerHTML'),  # DOM manipulation
                code.count('eval'),  # Dynamic execution
                code.count('exec'),
                code.count('system'),  # System calls
                code.count('strcpy'),  # Unsafe functions
            ])

            # CWE-based features
            cwe_id = sample.get('cwe_id', '')
            cwe_features = [0.0] * 10  # One-hot encoding for common CWEs

            common_cwes = ['CWE-79', 'CWE-89', 'CWE-120', 'CWE-352', 'CWE-22']
            for i, cwe in enumerate(common_cwes):
                if cwe in cwe_id:
                    cwe_features[i] = 1.0

            features.extend(cwe_features[:5])

            # Severity features
            severity_score = sample.get('severity_score', 0)
            features.append(float(severity_score))

            # Pad to fixed size
            target_size = 20
            if len(features) < target_size:
                features.extend([0.0] * (target_size - len(features)))
            else:
                features = features[:target_size]

            return features

        except Exception as e:
            self.logger.error(f"Failed to extract vulnerability features: {e}")
            return [0.0] * 20

    async def _extract_binary_features(self, sample: Dict[str, Any]) -> List[float]:
        """Extract features for binary analysis"""
        try:
            features = []

            # Assembly features
            assembly = sample.get('assembly_code', '')
            features.extend([
                len(assembly),
                assembly.count('mov'),
                assembly.count('call'),
                assembly.count('push'),
                assembly.count('pop'),
                assembly.count('jmp'),
            ])

            # Binary features
            binary_data = sample.get('binary_data', '')
            features.extend([
                len(binary_data),
                binary_data.count('\\x'),  # Hex bytes
            ])

            # Instruction count
            instruction_count = sample.get('instruction_count', 0)
            features.append(float(instruction_count))

            # Architecture features
            arch = sample.get('architecture', 'unknown')
            arch_features = [
                1.0 if 'x86' in arch else 0.0,
                1.0 if 'x64' in arch else 0.0,
                1.0 if 'arm' in arch else 0.0
            ]
            features.extend(arch_features)

            # Pad to fixed size
            target_size = 15
            if len(features) < target_size:
                features.extend([0.0] * (target_size - len(features)))
            else:
                features = features[:target_size]

            return features

        except Exception as e:
            self.logger.error(f"Failed to extract binary features: {e}")
            return [0.0] * 15

    async def _extract_api_features(self, sample: Dict[str, Any]) -> List[float]:
        """Extract features for API security analysis"""
        try:
            features = []

            # Pattern features
            pattern = sample.get('api_key_pattern', '')
            features.extend([
                len(pattern),
                pattern.count('['),  # Character classes
                pattern.count('+'),  # Quantifiers
                pattern.count('*'),
                pattern.count('?'),
            ])

            # Service features
            service_features = [0.0] * 5
            services = ['aws', 'google', 'github', 'stripe', 'slack']
            service_type = sample.get('service_type', '').lower()

            for i, service in enumerate(services):
                if service == service_type:
                    service_features[i] = 1.0

            features.extend(service_features)

            # Context features
            context_features = [0.0] * 4
            contexts = ['configuration_file', 'source_code', 'environment_variable', 'documentation']
            context = sample.get('context', '').lower()

            for i, ctx in enumerate(contexts):
                if ctx in context:
                    context_features[i] = 1.0

            features.extend(context_features)

            # Validation result
            validation = 1.0 if sample.get('validation_result') == 'valid' else 0.0
            features.append(validation)

            return features

        except Exception as e:
            self.logger.error(f"Failed to extract API features: {e}")
            return [0.0] * 15

    async def _calculate_batch_quality(self, features: List[List[float]], labels: List[Any]) -> float:
        """Calculate quality score for a training batch"""
        try:
            if not features or not labels:
                return 0.0

            # Check feature completeness
            feature_completeness = sum(1 for f in features if any(x != 0 for x in f)) / len(features)

            # Check label distribution
            if len(set(labels)) > 1:
                label_balance = min(labels.count(0), labels.count(1)) / len(labels) if 1 in labels and 0 in labels else 0.5
            else:
                label_balance = 0.1  # Poor balance

            # Calculate overall quality
            quality_score = (feature_completeness * 0.7) + (label_balance * 0.3)

            return min(1.0, quality_score)

        except Exception as e:
            self.logger.error(f"Failed to calculate batch quality: {e}")
            return 0.5

    async def get_dataset_statistics(self, dataset_names: List[str] = None) -> Dict[str, Any]:
        """Get statistics for loaded datasets"""
        try:
            dataset_names = dataset_names or list(self.datasets.keys())
            statistics = {}

            for dataset_name in dataset_names:
                if dataset_name not in self.datasets or '_data' in dataset_name:
                    continue

                dataset_info = self.datasets[dataset_name]
                data_key = f"{dataset_name}_data"

                stats = {
                    'basic_info': asdict(dataset_info),
                    'data_quality': {},
                    'feature_distribution': {},
                    'label_distribution': {}
                }

                # Get data quality metrics
                if data_key in self.datasets:
                    data = self.datasets[data_key]
                    stats['data_quality'] = await self._analyze_data_quality(data, dataset_name)

                statistics[dataset_name] = stats

            return statistics

        except Exception as e:
            self.logger.error(f"Failed to get dataset statistics: {e}")
            return {}

    async def _analyze_data_quality(self, data: List[Dict[str, Any]], dataset_name: str) -> Dict[str, Any]:
        """Analyze data quality for a dataset"""
        try:
            quality_metrics = {
                'completeness': 0.0,
                'consistency': 0.0,
                'validity': 0.0,
                'overall_score': 0.0
            }

            if not data:
                return quality_metrics

            # Completeness: percentage of non-empty values
            total_fields = 0
            complete_fields = 0

            for sample in data[:100]:  # Sample first 100 records
                for key, value in sample.items():
                    total_fields += 1
                    if value and str(value).strip():
                        complete_fields += 1

            quality_metrics['completeness'] = complete_fields / total_fields if total_fields > 0 else 0.0

            # Validity: percentage of samples that pass validation
            valid_samples = sum(1 for sample in data if self._is_valid_sample(sample, dataset_name))
            quality_metrics['validity'] = valid_samples / len(data)

            # Consistency: basic consistency checks
            consistency_score = 0.8  # Default assumption

            # Overall score
            quality_metrics['overall_score'] = (
                quality_metrics['completeness'] * 0.4 +
                quality_metrics['validity'] * 0.4 +
                consistency_score * 0.2
            )

            return quality_metrics

        except Exception as e:
            self.logger.error(f"Failed to analyze data quality: {e}")
            return {'completeness': 0.0, 'consistency': 0.0, 'validity': 0.0, 'overall_score': 0.0}

    async def update_dataset_with_assessment_results(self, assessment_results: Dict[str, Any]):
        """Update custom datasets with new assessment results"""
        try:
            self.logger.info("📊 Updating datasets with assessment results")

            # Extract new vulnerability samples
            vulnerabilities = []
            phases = assessment_results.get('phases', {})

            for phase_name, phase_data in phases.items():
                if isinstance(phase_data, dict):
                    phase_vulns = phase_data.get('vulnerabilities', [])
                    for vuln in phase_vulns:
                        vulnerability_sample = {
                            'code': vuln.get('description', ''),  # Use description as code proxy
                            'vulnerability_type': vuln.get('type', 'unknown'),
                            'severity': vuln.get('severity', 'medium').lower(),
                            'cwe_id': vuln.get('cwe_id', 'CWE-Unknown'),
                            'description': vuln.get('description', ''),
                            'source': 'assessment_result',
                            'timestamp': datetime.now().isoformat()
                        }
                        vulnerabilities.append(vulnerability_sample)

            # Update custom vulnerability dataset
            if vulnerabilities:
                if 'custom_vulnerabilities_data' in self.datasets:
                    self.datasets['custom_vulnerabilities_data'].extend(vulnerabilities)
                else:
                    self.datasets['custom_vulnerabilities_data'] = vulnerabilities

                # Update dataset info
                if 'custom_vulnerabilities' in self.datasets:
                    dataset_info = self.datasets['custom_vulnerabilities']
                    dataset_info.sample_count += len(vulnerabilities)
                    dataset_info.size += len(vulnerabilities)

                self.logger.info(f"📊 Added {len(vulnerabilities)} vulnerability samples to dataset")

        except Exception as e:
            self.logger.error(f"Failed to update dataset with assessment results: {e}")

    async def generate_dataset_report(self) -> Dict[str, Any]:
        """Generate comprehensive dataset report"""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'summary': {
                    'loaded_datasets': len([k for k in self.datasets.keys() if not k.endswith('_data')]),
                    'total_samples': sum(info.sample_count for info in self.datasets.values() if isinstance(info, DatasetInfo)),
                    'dataset_types': list(self.dataset_configs.keys())
                },
                'dataset_details': {},
                'quality_assessment': {},
                'training_readiness': {},
                'recommendations': []
            }

            # Get detailed statistics
            statistics = await self.get_dataset_statistics()
            report['dataset_details'] = statistics

            # Generate recommendations
            recommendations = await self._generate_dataset_recommendations(statistics)
            report['recommendations'] = recommendations

            return report

        except Exception as e:
            self.logger.error(f"Failed to generate dataset report: {e}")
            return {'error': str(e)}

    async def _generate_dataset_recommendations(self, statistics: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on dataset analysis"""
        recommendations = []

        try:
            for dataset_name, stats in statistics.items():
                quality = stats.get('data_quality', {})
                overall_score = quality.get('overall_score', 0.0)

                if overall_score < 0.7:
                    recommendations.append(f"Improve data quality for {dataset_name} dataset")

                if stats.get('basic_info', {}).get('sample_count', 0) < 1000:
                    recommendations.append(f"Collect more training samples for {dataset_name}")

            # General recommendations
            recommendations.extend([
                "Implement data validation pipelines",
                "Set up automated data quality monitoring",
                "Establish dataset versioning and lineage tracking",
                "Regular dataset refresh and updates",
                "Cross-validation of dataset quality metrics"
            ])

        except Exception as e:
            self.logger.error(f"Failed to generate dataset recommendations: {e}")

        return recommendations

# Global dataset integration instance
dataset_integration = VulnerabilityDatasetIntegration()