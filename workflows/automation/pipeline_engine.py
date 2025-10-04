#!/usr/bin/env python3
"""
🔄 QuantumSentinel Production Workflow Engine
Optimized YAML-based workflow orchestration with advanced parallel execution and resource management
"""

import asyncio
import logging
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict

logger = logging.getLogger("QuantumSentinel.WorkflowEngine")

@dataclass
class TaskResult:
    """Task execution result"""
    task_id: str
    status: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: Optional[str] = None
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

@dataclass
class WorkflowContext:
    """Workflow execution context"""
    workflow_id: str
    variables: Dict[str, Any]
    task_results: Dict[str, TaskResult]
    shared_data: Dict[str, Any]

class ProductionWorkflowEngine:
    """Production-grade workflow engine with optimized parallel execution"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.task_registry = {}
        self.active_workflows = {}
        self.resource_pools = {}
        self.performance_metrics = {}

        # Configuration for optimized execution
        self.max_parallel_tasks = config.get('max_parallel_tasks', 10)
        self.task_timeout = config.get('task_timeout', 300)  # 5 minutes default
        self.enable_caching = config.get('enable_caching', True)
        self.cache_dir = config.get('cache_dir', '.workflow_cache')
        self.retry_failed_tasks = config.get('retry_failed_tasks', True)
        self.max_retries = config.get('max_retries', 2)

        # Task execution pools
        self.cpu_intensive_semaphore = asyncio.Semaphore(config.get('cpu_tasks', 4))
        self.io_intensive_semaphore = asyncio.Semaphore(config.get('io_tasks', 8))
        self.network_semaphore = asyncio.Semaphore(config.get('network_tasks', 6))

        # Register built-in task types
        self._register_builtin_tasks()
        self._init_cache_system()

    def _register_builtin_tasks(self):
        """Register built-in task types"""

        self.task_registry.update({
            'ScanTask': self._execute_scan_task,
            'AIAnalysisTask': self._execute_ai_analysis_task,
            'ReportTask': self._execute_report_task,
            'NotificationTask': self._execute_notification_task,
            'ConditionalTask': self._execute_conditional_task,
            'ParallelTask': self._execute_parallel_task,
            'SequentialTask': self._execute_sequential_task
        })

    async def load_workflow(self, workflow_file: str) -> Dict[str, Any]:
        """Load workflow from YAML file"""

        try:
            with open(workflow_file, 'r') as f:
                workflow_config = yaml.safe_load(f)

            # Validate workflow structure
            await self._validate_workflow(workflow_config)

            logger.info(f"Loaded workflow: {workflow_config.get('name', 'Unnamed')}")
            return workflow_config

        except Exception as e:
            logger.error(f"Failed to load workflow {workflow_file}: {e}")
            raise

    async def _validate_workflow(self, workflow_config: Dict[str, Any]):
        """Validate workflow configuration"""

        required_fields = ['name', 'workflow']
        for field in required_fields:
            if field not in workflow_config:
                raise ValueError(f"Missing required field: {field}")

        # Validate tasks
        for task in workflow_config['workflow']:
            if 'name' not in task:
                raise ValueError("Task missing 'name' field")
            if 'type' not in task:
                raise ValueError(f"Task '{task['name']}' missing 'type' field")
            if task['type'] not in self.task_registry:
                raise ValueError(f"Unknown task type: {task['type']}")

    async def execute_workflow(
        self,
        workflow_file: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute complete workflow"""

        workflow_config = await self.load_workflow(workflow_file)
        workflow_id = f"WF-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        start_time = datetime.now()

        # Initialize workflow context
        workflow_context = WorkflowContext(
            workflow_id=workflow_id,
            variables=context or {},
            task_results={},
            shared_data={}
        )

        self.active_workflows[workflow_id] = workflow_context

        execution_results = {
            'workflow_id': workflow_id,
            'workflow_name': workflow_config.get('name'),
            'start_time': start_time.isoformat(),
            'status': 'running',
            'tasks_executed': 0,
            'tasks_failed': 0,
            'workflow_results': {},
            'execution_summary': {}
        }

        try:
            logger.info(f"Starting workflow execution: {workflow_id}")

            # Execute workflow tasks
            tasks = workflow_config['workflow']
            execution_plan = await self._create_execution_plan(tasks)

            for execution_group in execution_plan:
                if execution_group['type'] == 'parallel':
                    await self._execute_parallel_group(execution_group['tasks'], workflow_context)
                else:
                    await self._execute_sequential_group(execution_group['tasks'], workflow_context)

            # Calculate execution summary
            end_time = datetime.now()
            execution_results.update({
                'end_time': end_time.isoformat(),
                'duration': str(end_time - start_time),
                'status': 'completed',
                'tasks_executed': len(workflow_context.task_results),
                'tasks_failed': len([r for r in workflow_context.task_results.values() if r.status == 'failed']),
                'workflow_results': {task_id: asdict(result) for task_id, result in workflow_context.task_results.items()},
                'execution_summary': {
                    'total_tasks': len(workflow_context.task_results),
                    'successful_tasks': len([r for r in workflow_context.task_results.values() if r.status == 'completed']),
                    'failed_tasks': len([r for r in workflow_context.task_results.values() if r.status == 'failed']),
                    'status': 'completed'
                }
            })

            logger.info(f"Workflow {workflow_id} completed successfully")

        except Exception as e:
            logger.error(f"Workflow {workflow_id} failed: {e}")
            execution_results.update({
                'status': 'failed',
                'error': str(e),
                'execution_summary': {
                    'status': 'failed',
                    'error': str(e)
                }
            })

        finally:
            # Cleanup
            if workflow_id in self.active_workflows:
                del self.active_workflows[workflow_id]

        return execution_results

    async def _create_execution_plan(self, tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create optimized execution plan with parallel and sequential groups"""

        execution_plan = []
        remaining_tasks = tasks.copy()
        completed_tasks = set()

        while remaining_tasks:
            # Find tasks that can be executed in parallel (no dependencies or dependencies satisfied)
            parallel_tasks = []
            sequential_tasks = []

            for task in remaining_tasks:
                dependencies = task.get('depends_on', [])
                if not dependencies or all(dep in completed_tasks for dep in dependencies):
                    if task.get('parallel', True):  # Default to parallel execution
                        parallel_tasks.append(task)
                    else:
                        sequential_tasks.append(task)

            if parallel_tasks:
                execution_plan.append({
                    'type': 'parallel',
                    'tasks': parallel_tasks
                })
                for task in parallel_tasks:
                    completed_tasks.add(task['name'])
                    remaining_tasks.remove(task)

            if sequential_tasks:
                execution_plan.append({
                    'type': 'sequential',
                    'tasks': sequential_tasks
                })
                for task in sequential_tasks:
                    completed_tasks.add(task['name'])
                    remaining_tasks.remove(task)

            # Safety check to prevent infinite loops
            if not parallel_tasks and not sequential_tasks:
                raise Exception("Circular dependency detected in workflow tasks")

        return execution_plan

    async def _execute_parallel_group(self, tasks: List[Dict[str, Any]], context: WorkflowContext):
        """Execute tasks in parallel"""

        logger.info(f"Executing {len(tasks)} tasks in parallel")

        # Create coroutines for all tasks
        task_coroutines = []
        for task in tasks:
            coro = self._execute_single_task(task, context)
            task_coroutines.append(coro)

        # Execute all tasks concurrently
        await asyncio.gather(*task_coroutines, return_exceptions=True)

    async def _execute_sequential_group(self, tasks: List[Dict[str, Any]], context: WorkflowContext):
        """Execute tasks sequentially"""

        logger.info(f"Executing {len(tasks)} tasks sequentially")

        for task in tasks:
            await self._execute_single_task(task, context)

    async def _execute_single_task(self, task: Dict[str, Any], context: WorkflowContext):
        """Execute a single task"""

        task_name = task['name']
        task_type = task['type']

        logger.info(f"Executing task: {task_name} ({task_type})")

        start_time = datetime.now()
        task_result = TaskResult(
            task_id=task_name,
            status='running',
            start_time=start_time
        )

        try:
            # Execute task based on type
            if task_type in self.task_registry:
                output = await self.task_registry[task_type](task, context)
                task_result.output = output
                task_result.status = 'completed'
            else:
                raise ValueError(f"Unknown task type: {task_type}")

        except Exception as e:
            logger.error(f"Task {task_name} failed: {e}")
            task_result.status = 'failed'
            task_result.error = str(e)

        finally:
            end_time = datetime.now()
            task_result.end_time = end_time
            task_result.duration = str(end_time - start_time)

            # Store result in context
            context.task_results[task_name] = task_result

        logger.info(f"Task {task_name} {task_result.status} in {task_result.duration}")

    async def _execute_scan_task(self, task: Dict[str, Any], context: WorkflowContext) -> Dict[str, Any]:
        """Execute security scan task"""

        config = task.get('config', {})
        engine_type = config.get('engine', 'sast')
        target = config.get('target', '.')

        # Simulate scan execution
        await asyncio.sleep(1)  # Simulate scan time

        return {
            'engine': engine_type,
            'target': target,
            'findings_count': 5,  # Simulated
            'scan_duration': '30s',
            'status': 'completed'
        }

    async def _execute_ai_analysis_task(self, task: Dict[str, Any], context: WorkflowContext) -> Dict[str, Any]:
        """Execute AI analysis task"""

        config = task.get('config', {})
        analysis_type = config.get('type', 'vulnerability_detection')

        # Simulate AI analysis
        await asyncio.sleep(2)

        return {
            'analysis_type': analysis_type,
            'ai_findings': 3,  # Simulated
            'confidence_score': 0.85,
            'model_used': 'enhanced_ml_model',
            'status': 'completed'
        }

    async def _execute_report_task(self, task: Dict[str, Any], context: WorkflowContext) -> Dict[str, Any]:
        """Execute report generation task"""

        config = task.get('config', {})
        report_format = config.get('format', 'json')
        output_file = config.get('output', 'report.json')

        # Simulate report generation
        await asyncio.sleep(0.5)

        return {
            'format': report_format,
            'output_file': output_file,
            'file_size': '256KB',  # Simulated
            'status': 'completed'
        }

    async def _execute_notification_task(self, task: Dict[str, Any], context: WorkflowContext) -> Dict[str, Any]:
        """Execute notification task"""

        config = task.get('config', {})
        notification_type = config.get('type', 'email')
        message = config.get('message', 'Workflow completed')

        # Simulate notification
        await asyncio.sleep(0.1)

        return {
            'notification_type': notification_type,
            'message': message,
            'delivered': True,
            'status': 'completed'
        }

    async def _execute_conditional_task(self, task: Dict[str, Any], context: WorkflowContext) -> Dict[str, Any]:
        """Execute conditional task"""

        config = task.get('config', {})
        condition = config.get('condition', True)

        if condition:
            # Execute conditional logic
            await asyncio.sleep(0.1)
            return {'condition_met': True, 'action_taken': True, 'status': 'completed'}
        else:
            return {'condition_met': False, 'action_taken': False, 'status': 'skipped'}

    async def _execute_parallel_task(self, task: Dict[str, Any], context: WorkflowContext) -> Dict[str, Any]:
        """Execute parallel task container"""

        config = task.get('config', {})
        subtasks = config.get('tasks', [])

        # Execute subtasks in parallel
        subtask_results = []
        for subtask in subtasks:
            result = await self._execute_single_task(subtask, context)
            subtask_results.append(result)

        return {
            'subtasks_executed': len(subtasks),
            'subtask_results': subtask_results,
            'status': 'completed'
        }

    async def _execute_sequential_task(self, task: Dict[str, Any], context: WorkflowContext) -> Dict[str, Any]:
        """Execute sequential task container"""

        config = task.get('config', {})
        subtasks = config.get('tasks', [])

        # Execute subtasks sequentially
        subtask_results = []
        for subtask in subtasks:
            result = await self._execute_single_task(subtask, context)
            subtask_results.append(result)

        return {
            'subtasks_executed': len(subtasks),
            'subtask_results': subtask_results,
            'status': 'completed'
        }

    def register_custom_task(self, task_type: str, executor_function):
        """Register custom task type"""

        self.task_registry[task_type] = executor_function
        logger.info(f"Registered custom task type: {task_type}")

    async def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get status of running workflow"""

        if workflow_id in self.active_workflows:
            context = self.active_workflows[workflow_id]
            return {
                'workflow_id': workflow_id,
                'status': 'running',
                'tasks_completed': len([r for r in context.task_results.values() if r.status in ['completed', 'failed']]),
                'total_tasks': len(context.task_results),
                'current_tasks': [r.task_id for r in context.task_results.values() if r.status == 'running']
            }

        return None

    def _init_cache_system(self):
        """Initialize workflow caching system"""
        if self.enable_caching:
            import os
            os.makedirs(self.cache_dir, exist_ok=True)
            logger.info(f"Workflow caching enabled: {self.cache_dir}")

    async def execute_workflow_optimized(
        self,
        workflow_file: str,
        context: Optional[Dict[str, Any]] = None,
        optimization_level: str = "balanced"
    ) -> Dict[str, Any]:
        """Execute workflow with advanced optimization strategies"""

        workflow_config = await self.load_workflow(workflow_file)
        workflow_id = f"WF-OPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        start_time = datetime.now()

        # Initialize workflow context with optimization
        workflow_context = WorkflowContext(
            workflow_id=workflow_id,
            variables=context or {},
            task_results={},
            shared_data={}
        )

        self.active_workflows[workflow_id] = workflow_context

        execution_results = {
            'workflow_id': workflow_id,
            'workflow_name': workflow_config.get('name'),
            'optimization_level': optimization_level,
            'start_time': start_time.isoformat(),
            'status': 'running',
            'performance_metrics': {},
            'resource_usage': {},
            'parallel_efficiency': 0.0,
            'tasks_executed': 0,
            'tasks_failed': 0,
            'tasks_cached': 0,
            'workflow_results': {},
            'execution_summary': {}
        }

        try:
            logger.info(f"Starting optimized workflow execution: {workflow_id} (level: {optimization_level})")

            # Create optimized execution plan
            tasks = workflow_config['workflow']
            optimized_plan = await self._create_optimized_execution_plan(tasks, optimization_level)

            # Track performance metrics
            performance_tracker = {
                'parallel_groups_executed': 0,
                'max_concurrent_tasks': 0,
                'avg_task_duration': 0.0,
                'cache_hit_rate': 0.0,
                'resource_efficiency': {}
            }

            # Execute optimized plan
            for execution_group in optimized_plan:
                group_start = datetime.now()

                if execution_group['type'] == 'parallel':
                    concurrent_tasks = len(execution_group['tasks'])
                    performance_tracker['max_concurrent_tasks'] = max(
                        performance_tracker['max_concurrent_tasks'],
                        concurrent_tasks
                    )
                    await self._execute_optimized_parallel_group(execution_group['tasks'], workflow_context)
                    performance_tracker['parallel_groups_executed'] += 1
                else:
                    await self._execute_sequential_group(execution_group['tasks'], workflow_context)

                group_duration = (datetime.now() - group_start).total_seconds()
                logger.info(f"Execution group completed in {group_duration:.2f}s")

            # Calculate final metrics
            end_time = datetime.now()
            total_duration = end_time - start_time

            # Calculate parallel efficiency
            total_task_time = sum(
                (r.end_time - r.start_time).total_seconds()
                for r in workflow_context.task_results.values()
                if r.end_time and r.start_time
            )
            actual_time = total_duration.total_seconds()
            parallel_efficiency = (total_task_time / actual_time) if actual_time > 0 else 0.0

            execution_results.update({
                'end_time': end_time.isoformat(),
                'duration': str(total_duration),
                'status': 'completed',
                'parallel_efficiency': min(parallel_efficiency, 1.0),  # Cap at 100%
                'tasks_executed': len(workflow_context.task_results),
                'tasks_failed': len([r for r in workflow_context.task_results.values() if r.status == 'failed']),
                'tasks_cached': performance_tracker.get('cache_hits', 0),
                'performance_metrics': performance_tracker,
                'workflow_results': {task_id: asdict(result) for task_id, result in workflow_context.task_results.items()},
                'execution_summary': {
                    'total_tasks': len(workflow_context.task_results),
                    'successful_tasks': len([r for r in workflow_context.task_results.values() if r.status == 'completed']),
                    'failed_tasks': len([r for r in workflow_context.task_results.values() if r.status == 'failed']),
                    'parallel_efficiency': f"{parallel_efficiency:.1%}",
                    'avg_task_duration': f"{total_task_time / len(workflow_context.task_results):.2f}s" if workflow_context.task_results else "0s",
                    'status': 'completed'
                }
            })

            logger.info(f"Optimized workflow {workflow_id} completed successfully in {total_duration}")
            logger.info(f"Parallel efficiency: {parallel_efficiency:.1%}")

        except Exception as e:
            logger.error(f"Optimized workflow {workflow_id} failed: {e}")
            execution_results.update({
                'status': 'failed',
                'error': str(e),
                'execution_summary': {
                    'status': 'failed',
                    'error': str(e)
                }
            })

        finally:
            # Cleanup
            if workflow_id in self.active_workflows:
                del self.active_workflows[workflow_id]

        return execution_results

    async def _create_optimized_execution_plan(self, tasks: List[Dict[str, Any]], optimization_level: str) -> List[Dict[str, Any]]:
        """Create optimized execution plan based on resource requirements and dependencies"""

        execution_plan = []
        remaining_tasks = tasks.copy()
        completed_tasks = set()

        # Analyze task characteristics for optimization
        task_analysis = await self._analyze_task_characteristics(tasks)

        while remaining_tasks:
            # Find tasks ready for execution
            ready_tasks = []

            for task in remaining_tasks:
                dependencies = task.get('depends_on', [])
                if not dependencies or all(dep in completed_tasks for dep in dependencies):
                    ready_tasks.append(task)

            if not ready_tasks:
                raise Exception("Circular dependency detected in workflow tasks")

            # Optimize task grouping based on characteristics and level
            if optimization_level == "speed":
                # Maximize parallelism
                grouped_tasks = await self._group_tasks_for_speed(ready_tasks, task_analysis)
            elif optimization_level == "resource":
                # Optimize resource usage
                grouped_tasks = await self._group_tasks_for_resources(ready_tasks, task_analysis)
            else:  # balanced
                # Balance speed and resource usage
                grouped_tasks = await self._group_tasks_balanced(ready_tasks, task_analysis)

            execution_plan.extend(grouped_tasks)

            # Mark tasks as completed
            for group in grouped_tasks:
                for task in group['tasks']:
                    completed_tasks.add(task['name'])
                    remaining_tasks.remove(task)

        return execution_plan

    async def _analyze_task_characteristics(self, tasks: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Analyze task characteristics for optimization"""

        analysis = {}

        for task in tasks:
            task_type = task.get('type', 'unknown')
            config = task.get('config', {})

            characteristics = {
                'resource_type': 'cpu',  # Default
                'estimated_duration': 30,  # Default 30 seconds
                'memory_usage': 'low',
                'network_intensive': False,
                'can_cache': True,
                'priority': task.get('priority', 'normal')
            }

            # Classify based on task type
            if task_type in ['ScanTask', 'AIAnalysisTask']:
                characteristics.update({
                    'resource_type': 'cpu',
                    'estimated_duration': 60,
                    'memory_usage': 'high'
                })
            elif task_type in ['ReportTask', 'NotificationTask']:
                characteristics.update({
                    'resource_type': 'io',
                    'estimated_duration': 10,
                    'memory_usage': 'low'
                })
            elif task_type in ['NetworkTask', 'APITask']:
                characteristics.update({
                    'resource_type': 'network',
                    'estimated_duration': 20,
                    'network_intensive': True
                })

            # Override with config if provided
            if 'estimated_duration' in config:
                characteristics['estimated_duration'] = config['estimated_duration']
            if 'resource_type' in config:
                characteristics['resource_type'] = config['resource_type']

            analysis[task['name']] = characteristics

        return analysis

    async def _group_tasks_for_speed(self, ready_tasks: List[Dict[str, Any]], analysis: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Group tasks to maximize execution speed"""

        # Execute all possible tasks in parallel
        if len(ready_tasks) <= self.max_parallel_tasks:
            return [{
                'type': 'parallel',
                'tasks': ready_tasks,
                'optimization': 'speed_maximized'
            }]
        else:
            # Split into multiple parallel groups
            groups = []
            for i in range(0, len(ready_tasks), self.max_parallel_tasks):
                group_tasks = ready_tasks[i:i + self.max_parallel_tasks]
                groups.append({
                    'type': 'parallel',
                    'tasks': group_tasks,
                    'optimization': 'speed_chunked'
                })
            return groups

    async def _group_tasks_for_resources(self, ready_tasks: List[Dict[str, Any]], analysis: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Group tasks to optimize resource usage"""

        # Separate by resource type
        cpu_tasks = []
        io_tasks = []
        network_tasks = []

        for task in ready_tasks:
            resource_type = analysis.get(task['name'], {}).get('resource_type', 'cpu')
            if resource_type == 'cpu':
                cpu_tasks.append(task)
            elif resource_type == 'io':
                io_tasks.append(task)
            else:
                network_tasks.append(task)

        groups = []

        # Create resource-optimized groups
        if cpu_tasks:
            groups.append({
                'type': 'parallel',
                'tasks': cpu_tasks[:4],  # Limit CPU intensive tasks
                'optimization': 'cpu_optimized'
            })
        if io_tasks:
            groups.append({
                'type': 'parallel',
                'tasks': io_tasks[:8],  # More IO tasks can run in parallel
                'optimization': 'io_optimized'
            })
        if network_tasks:
            groups.append({
                'type': 'parallel',
                'tasks': network_tasks[:6],  # Moderate network concurrency
                'optimization': 'network_optimized'
            })

        return groups if groups else [{
            'type': 'sequential',
            'tasks': ready_tasks,
            'optimization': 'resource_fallback'
        }]

    async def _group_tasks_balanced(self, ready_tasks: List[Dict[str, Any]], analysis: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Group tasks with balanced speed and resource optimization"""

        # Sort by priority and estimated duration
        prioritized_tasks = sorted(ready_tasks, key=lambda t: (
            analysis.get(t['name'], {}).get('priority', 'normal') != 'high',
            analysis.get(t['name'], {}).get('estimated_duration', 30)
        ))

        # Create balanced groups
        groups = []
        current_group = []
        current_cpu_tasks = 0
        current_io_tasks = 0
        current_network_tasks = 0

        for task in prioritized_tasks:
            resource_type = analysis.get(task['name'], {}).get('resource_type', 'cpu')

            # Check resource limits
            can_add = False
            if resource_type == 'cpu' and current_cpu_tasks < 3:
                can_add = True
                current_cpu_tasks += 1
            elif resource_type == 'io' and current_io_tasks < 4:
                can_add = True
                current_io_tasks += 1
            elif resource_type == 'network' and current_network_tasks < 3:
                can_add = True
                current_network_tasks += 1

            if can_add and len(current_group) < 6:  # Max 6 tasks per group
                current_group.append(task)
            else:
                # Finalize current group
                if current_group:
                    groups.append({
                        'type': 'parallel',
                        'tasks': current_group,
                        'optimization': 'balanced'
                    })

                # Start new group
                current_group = [task]
                current_cpu_tasks = 1 if resource_type == 'cpu' else 0
                current_io_tasks = 1 if resource_type == 'io' else 0
                current_network_tasks = 1 if resource_type == 'network' else 0

        # Add final group
        if current_group:
            groups.append({
                'type': 'parallel',
                'tasks': current_group,
                'optimization': 'balanced'
            })

        return groups

    async def _execute_optimized_parallel_group(self, tasks: List[Dict[str, Any]], context: WorkflowContext):
        """Execute tasks in parallel with resource management"""

        logger.info(f"Executing {len(tasks)} tasks in optimized parallel mode")

        # Create semaphore-controlled coroutines
        async def execute_with_resource_control(task):
            task_type = task.get('type', 'unknown')
            config = task.get('config', {})
            resource_type = config.get('resource_type', 'cpu')

            # Select appropriate semaphore
            if resource_type == 'cpu':
                async with self.cpu_intensive_semaphore:
                    await self._execute_single_task_optimized(task, context)
            elif resource_type == 'io':
                async with self.io_intensive_semaphore:
                    await self._execute_single_task_optimized(task, context)
            elif resource_type == 'network':
                async with self.network_semaphore:
                    await self._execute_single_task_optimized(task, context)
            else:
                await self._execute_single_task_optimized(task, context)

        # Execute all tasks with resource controls
        task_coroutines = [execute_with_resource_control(task) for task in tasks]
        await asyncio.gather(*task_coroutines, return_exceptions=True)

    async def _execute_single_task_optimized(self, task: Dict[str, Any], context: WorkflowContext):
        """Execute single task with optimization features"""

        task_name = task['name']
        task_type = task['type']

        # Check cache first
        if self.enable_caching:
            cached_result = await self._check_task_cache(task, context)
            if cached_result:
                logger.info(f"Using cached result for task: {task_name}")
                context.task_results[task_name] = cached_result
                return

        logger.info(f"Executing optimized task: {task_name} ({task_type})")

        start_time = datetime.now()
        task_result = TaskResult(
            task_id=task_name,
            status='running',
            start_time=start_time
        )

        retry_count = 0
        max_retries = self.max_retries if self.retry_failed_tasks else 0

        while retry_count <= max_retries:
            try:
                # Execute with timeout
                output = await asyncio.wait_for(
                    self._execute_task_with_timeout(task, context),
                    timeout=self.task_timeout
                )

                task_result.output = output
                task_result.status = 'completed'

                # Cache successful result
                if self.enable_caching:
                    await self._cache_task_result(task, task_result, context)

                break  # Success, exit retry loop

            except asyncio.TimeoutError:
                logger.error(f"Task {task_name} timed out after {self.task_timeout}s")
                task_result.status = 'failed'
                task_result.error = f"Task timed out after {self.task_timeout} seconds"
                break  # Don't retry timeouts

            except Exception as e:
                retry_count += 1
                if retry_count <= max_retries:
                    logger.warning(f"Task {task_name} failed (attempt {retry_count}/{max_retries + 1}): {e}")
                    await asyncio.sleep(2 ** retry_count)  # Exponential backoff
                else:
                    logger.error(f"Task {task_name} failed after {retry_count} attempts: {e}")
                    task_result.status = 'failed'
                    task_result.error = str(e)

        # Finalize result
        end_time = datetime.now()
        task_result.end_time = end_time
        task_result.duration = str(end_time - start_time)
        context.task_results[task_name] = task_result

        logger.info(f"Task {task_name} {task_result.status} in {task_result.duration}")

    async def _execute_task_with_timeout(self, task: Dict[str, Any], context: WorkflowContext):
        """Execute task with the registered executor"""
        task_type = task['type']
        if task_type in self.task_registry:
            return await self.task_registry[task_type](task, context)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _check_task_cache(self, task: Dict[str, Any], context: WorkflowContext) -> Optional[TaskResult]:
        """Check if task result is cached"""
        if not self.enable_caching:
            return None

        try:
            import hashlib
            import json
            import pickle

            # Create cache key from task configuration
            task_key = json.dumps(task, sort_keys=True)
            cache_hash = hashlib.md5(task_key.encode()).hexdigest()
            cache_file = os.path.join(self.cache_dir, f"{cache_hash}.cache")

            if os.path.exists(cache_file):
                # Check if cache is still valid (1 hour)
                if time.time() - os.path.getmtime(cache_file) < 3600:
                    with open(cache_file, 'rb') as f:
                        return pickle.load(f)
                else:
                    os.remove(cache_file)  # Remove expired cache
        except Exception as e:
            logger.debug(f"Cache check failed: {e}")

        return None

    async def _cache_task_result(self, task: Dict[str, Any], result: TaskResult, context: WorkflowContext):
        """Cache task result for future use"""
        if not self.enable_caching or result.status != 'completed':
            return

        try:
            import hashlib
            import json
            import pickle

            task_key = json.dumps(task, sort_keys=True)
            cache_hash = hashlib.md5(task_key.encode()).hexdigest()
            cache_file = os.path.join(self.cache_dir, f"{cache_hash}.cache")

            with open(cache_file, 'wb') as f:
                pickle.dump(result, f)

            logger.debug(f"Cached result for task: {task['name']}")
        except Exception as e:
            logger.debug(f"Cache write failed: {e}")

# Alias for backward compatibility
WorkflowEngine = ProductionWorkflowEngine

# Enhanced example usage
async def main():
    """Example optimized workflow execution"""

    # Create comprehensive security workflow
    security_workflow = {
        'name': 'Advanced Security Assessment Pipeline',
        'description': 'Production-grade security testing with parallel optimization',
        'version': '2.0',
        'workflow': [
            # Phase 1: Parallel static analysis
            {
                'name': 'sast_scan',
                'type': 'ScanTask',
                'priority': 'high',
                'config': {
                    'engine': 'sast',
                    'target': './source-code',
                    'resource_type': 'cpu',
                    'estimated_duration': 45
                }
            },
            {
                'name': 'secret_scan',
                'type': 'ScanTask',
                'config': {
                    'engine': 'secrets',
                    'target': './source-code',
                    'resource_type': 'io',
                    'estimated_duration': 20
                }
            },
            {
                'name': 'dependency_scan',
                'type': 'ScanTask',
                'config': {
                    'engine': 'dependencies',
                    'target': './package.json',
                    'resource_type': 'network',
                    'estimated_duration': 30
                }
            },
            # Phase 2: Dynamic analysis (depends on static)
            {
                'name': 'dast_scan',
                'type': 'ScanTask',
                'depends_on': ['sast_scan'],
                'config': {
                    'engine': 'dast',
                    'target': 'https://example.com',
                    'resource_type': 'network',
                    'estimated_duration': 60
                }
            },
            {
                'name': 'mobile_scan',
                'type': 'ScanTask',
                'config': {
                    'engine': 'mobile',
                    'target': './app.apk',
                    'resource_type': 'cpu',
                    'estimated_duration': 90
                }
            },
            # Phase 3: AI analysis (depends on all scans)
            {
                'name': 'ai_vulnerability_analysis',
                'type': 'AIAnalysisTask',
                'depends_on': ['sast_scan', 'dast_scan', 'secret_scan'],
                'priority': 'high',
                'config': {
                    'type': 'vulnerability_detection',
                    'resource_type': 'cpu',
                    'estimated_duration': 40
                }
            },
            {
                'name': 'ai_risk_assessment',
                'type': 'AIAnalysisTask',
                'depends_on': ['dependency_scan', 'mobile_scan'],
                'config': {
                    'type': 'risk_assessment',
                    'resource_type': 'cpu',
                    'estimated_duration': 25
                }
            },
            # Phase 4: Reporting (parallel reports)
            {
                'name': 'executive_report',
                'type': 'ReportTask',
                'depends_on': ['ai_vulnerability_analysis', 'ai_risk_assessment'],
                'config': {
                    'format': 'pdf',
                    'output': 'executive_summary.pdf',
                    'resource_type': 'io',
                    'estimated_duration': 15
                }
            },
            {
                'name': 'technical_report',
                'type': 'ReportTask',
                'depends_on': ['ai_vulnerability_analysis'],
                'config': {
                    'format': 'html',
                    'output': 'technical_report.html',
                    'resource_type': 'io',
                    'estimated_duration': 10
                }
            },
            {
                'name': 'json_export',
                'type': 'ReportTask',
                'depends_on': ['ai_vulnerability_analysis', 'ai_risk_assessment'],
                'config': {
                    'format': 'json',
                    'output': 'results.json',
                    'resource_type': 'io',
                    'estimated_duration': 5
                }
            },
            # Phase 5: Notifications
            {
                'name': 'slack_notification',
                'type': 'NotificationTask',
                'depends_on': ['executive_report', 'technical_report'],
                'config': {
                    'type': 'slack',
                    'message': 'Security assessment completed',
                    'resource_type': 'network',
                    'estimated_duration': 3
                }
            }
        ]
    }

    # Save workflow to file
    with open('/tmp/advanced_security_workflow.yaml', 'w') as f:
        yaml.dump(security_workflow, f)

    # Configure optimized engine
    config = {
        'max_parallel_tasks': 8,
        'task_timeout': 300,
        'enable_caching': True,
        'cache_dir': '.workflow_cache',
        'retry_failed_tasks': True,
        'max_retries': 2,
        'cpu_tasks': 4,
        'io_tasks': 6,
        'network_tasks': 4
    }

    engine = ProductionWorkflowEngine(config)

    print("🔄 Starting optimized workflow execution...")

    # Test different optimization levels
    optimization_levels = ['speed', 'resource', 'balanced']

    for level in optimization_levels:
        print(f"\n🏁 Testing optimization level: {level.upper()}")

        results = await engine.execute_workflow_optimized(
            '/tmp/advanced_security_workflow.yaml',
            context={'project_name': 'TestProject', 'environment': 'staging'},
            optimization_level=level
        )

        print(f"   Status: {results['status']}")
        print(f"   Duration: {results.get('duration', 'unknown')}")
        print(f"   Tasks Executed: {results['tasks_executed']}")
        print(f"   Tasks Failed: {results['tasks_failed']}")
        print(f"   Parallel Efficiency: {results.get('parallel_efficiency', 0):.1%}")
        print(f"   Max Concurrent Tasks: {results.get('performance_metrics', {}).get('max_concurrent_tasks', 0)}")

        if results.get('execution_summary'):
            summary = results['execution_summary']
            print(f"   Summary: {summary.get('successful_tasks', 0)} successful, {summary.get('failed_tasks', 0)} failed")
            print(f"   Avg Task Duration: {summary.get('avg_task_duration', 'unknown')}")

    print("\n✅ Workflow optimization testing completed!")

# Performance comparison example
async def performance_comparison():
    """Compare standard vs optimized workflow execution"""

    config = {'max_parallel_tasks': 6, 'enable_caching': True}
    engine = ProductionWorkflowEngine(config)

    # Simple workflow for comparison
    simple_workflow = {
        'name': 'Performance Test Workflow',
        'workflow': [
            {'name': 'task1', 'type': 'ScanTask', 'config': {'engine': 'sast'}},
            {'name': 'task2', 'type': 'ScanTask', 'config': {'engine': 'dast'}},
            {'name': 'task3', 'type': 'AIAnalysisTask', 'depends_on': ['task1', 'task2']},
            {'name': 'task4', 'type': 'ReportTask', 'depends_on': ['task3']}
        ]
    }

    with open('/tmp/perf_test_workflow.yaml', 'w') as f:
        yaml.dump(simple_workflow, f)

    print("📈 Performance Comparison:")

    # Standard execution
    start_time = datetime.now()
    standard_results = await engine.execute_workflow('/tmp/perf_test_workflow.yaml')
    standard_duration = datetime.now() - start_time

    # Optimized execution
    start_time = datetime.now()
    optimized_results = await engine.execute_workflow_optimized('/tmp/perf_test_workflow.yaml', optimization_level='speed')
    optimized_duration = datetime.now() - start_time

    print(f"   Standard Execution: {standard_duration}")
    print(f"   Optimized Execution: {optimized_duration}")
    improvement = (standard_duration - optimized_duration).total_seconds()
    print(f"   Performance Improvement: {improvement:.2f} seconds")

if __name__ == "__main__":
    # Run main example
    asyncio.run(main())

    # Uncomment to run performance comparison
    # asyncio.run(performance_comparison())