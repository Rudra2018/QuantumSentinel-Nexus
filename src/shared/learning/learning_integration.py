"""
Learning Integration Module
Integrates adaptive learning across all security agents and orchestrators
"""
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
import json
import inspect
from functools import wraps

from .adaptive_learning_system import AdaptiveLearningSystem, LearningEvent

@dataclass
class AgentPerformanceMetrics:
    """Performance metrics for agent evaluation"""
    agent_id: str
    agent_type: str
    execution_time: float
    success_rate: float
    confidence_score: float
    findings_count: int
    error_count: int
    resource_usage: Dict[str, Any]
    timestamp: datetime

class LearningIntegration:
    """Centralized learning integration for all security components"""

    def __init__(self, learning_system: AdaptiveLearningSystem):
        self.learning_system = learning_system
        self.logger = logging.getLogger(__name__)
        self.active_sessions = {}
        self.performance_cache = {}

    def learning_enabled(self, agent_type: str = None):
        """Decorator to enable learning for agent methods"""
        def decorator(func: Callable):
            @wraps(func)
            async def wrapper(self_instance, *args, **kwargs):
                # Create learning session
                session_id = f"{agent_type or 'unknown'}_{func.__name__}_{datetime.now().timestamp()}"

                # Capture context
                context = await self._capture_execution_context(
                    self_instance, func, args, kwargs
                )

                start_time = datetime.now()
                success_score = 0.0
                confidence = 0.5
                outcome = "unknown"
                error = None

                try:
                    # Get pre-execution recommendations
                    recommendations = await self.learning_system.get_recommendations(
                        agent_type or 'general', context
                    )

                    # Predict success probability
                    predicted_success = await self.learning_system.predict_success(
                        agent_type or 'general', func.__name__, context
                    )

                    # Execute the original function
                    result = await func(self_instance, *args, **kwargs)

                    # Evaluate success
                    success_score, confidence, outcome = await self._evaluate_execution_result(
                        result, context, predicted_success
                    )

                    return result

                except Exception as e:
                    error = str(e)
                    success_score = 0.0
                    confidence = 0.8
                    outcome = f"error: {error}"
                    raise

                finally:
                    # Record learning event
                    execution_time = (datetime.now() - start_time).total_seconds()

                    event = LearningEvent(
                        event_id=session_id,
                        timestamp=start_time,
                        agent_type=agent_type or 'general',
                        action_type=func.__name__,
                        context=context,
                        outcome=outcome,
                        success_score=success_score,
                        confidence=confidence,
                        metadata={
                            'execution_time': execution_time,
                            'error': error,
                            'function_signature': str(inspect.signature(func)),
                            'args_count': len(args),
                            'kwargs_keys': list(kwargs.keys())
                        }
                    )

                    await self.learning_system.record_learning_event(event)

                    # Record performance metrics
                    await self._record_performance_metrics(
                        self_instance, agent_type, execution_time, success_score,
                        confidence, context
                    )

            return wrapper
        return decorator

    async def _capture_execution_context(self, instance: Any, func: Callable,
                                       args: tuple, kwargs: dict) -> Dict[str, Any]:
        """Capture execution context for learning"""
        context = {}

        try:
            # Basic function info
            context['function_name'] = func.__name__
            context['args_count'] = len(args)
            context['has_kwargs'] = len(kwargs) > 0

            # Instance attributes (if available)
            if hasattr(instance, 'config'):
                context['config'] = getattr(instance, 'config', {})

            # Extract meaningful parameters
            sig = inspect.signature(func)
            bound_args = sig.bind(instance, *args, **kwargs)
            bound_args.apply_defaults()

            for param_name, param_value in bound_args.arguments.items():
                if param_name == 'self':
                    continue

                # Store serializable parameters
                if isinstance(param_value, (str, int, float, bool, list, dict)):
                    context[f'param_{param_name}'] = param_value
                elif hasattr(param_value, '__dict__'):
                    # Extract simple attributes from objects
                    obj_attrs = {}
                    for attr_name, attr_value in param_value.__dict__.items():
                        if isinstance(attr_value, (str, int, float, bool)):
                            obj_attrs[attr_name] = attr_value
                    if obj_attrs:
                        context[f'param_{param_name}_attrs'] = obj_attrs

            # Environment context
            context['timestamp'] = datetime.now().isoformat()

            # Instance-specific context
            if hasattr(instance, 'get_context'):
                instance_context = await instance.get_context()
                context.update(instance_context)

            return context

        except Exception as e:
            self.logger.warning(f"Failed to capture execution context: {e}")
            return {'error': str(e), 'function_name': func.__name__}

    async def _evaluate_execution_result(self, result: Any, context: Dict[str, Any],
                                       predicted_success: float) -> tuple[float, float, str]:
        """Evaluate execution result for learning"""
        try:
            success_score = 0.5
            confidence = 0.5
            outcome = "unknown"

            # Result-based evaluation
            if result is None:
                success_score = 0.1
                outcome = "null_result"
            elif isinstance(result, bool):
                success_score = 1.0 if result else 0.0
                confidence = 0.9
                outcome = "success" if result else "failure"
            elif isinstance(result, dict):
                # Evaluate based on common result patterns
                if 'error' in result or 'errors' in result:
                    success_score = 0.2
                    outcome = "error_in_result"
                elif 'findings' in result:
                    findings_count = len(result.get('findings', []))
                    if findings_count > 0:
                        success_score = min(1.0, 0.5 + (findings_count * 0.1))
                        outcome = f"found_{findings_count}_findings"
                    else:
                        success_score = 0.3
                        outcome = "no_findings"
                elif 'success' in result:
                    success_score = 1.0 if result['success'] else 0.0
                    outcome = "explicit_success" if result['success'] else "explicit_failure"
                elif len(result) > 0:
                    success_score = 0.7
                    outcome = "non_empty_result"
                else:
                    success_score = 0.2
                    outcome = "empty_result"

                confidence = 0.8

            elif isinstance(result, list):
                if len(result) > 0:
                    success_score = min(1.0, 0.5 + (len(result) * 0.05))
                    outcome = f"list_with_{len(result)}_items"
                else:
                    success_score = 0.3
                    outcome = "empty_list"
                confidence = 0.7

            elif isinstance(result, str):
                if len(result) > 0:
                    success_score = 0.6
                    outcome = "non_empty_string"
                else:
                    success_score = 0.2
                    outcome = "empty_string"
                confidence = 0.6

            else:
                # Non-null result of unknown type
                success_score = 0.6
                outcome = f"result_type_{type(result).__name__}"
                confidence = 0.5

            # Adjust confidence based on prediction accuracy
            if abs(predicted_success - success_score) < 0.2:
                confidence += 0.1  # Good prediction increases confidence

            confidence = min(1.0, confidence)

            return success_score, confidence, outcome

        except Exception as e:
            self.logger.error(f"Failed to evaluate execution result: {e}")
            return 0.0, 0.5, f"evaluation_error: {str(e)}"

    async def _record_performance_metrics(self, instance: Any, agent_type: str,
                                        execution_time: float, success_score: float,
                                        confidence: float, context: Dict[str, Any]):
        """Record detailed performance metrics"""
        try:
            metrics = AgentPerformanceMetrics(
                agent_id=getattr(instance, 'agent_id', 'unknown'),
                agent_type=agent_type or 'general',
                execution_time=execution_time,
                success_rate=success_score,
                confidence_score=confidence,
                findings_count=context.get('findings_count', 0),
                error_count=1 if success_score < 0.3 else 0,
                resource_usage={
                    'execution_time': execution_time,
                    'context_size': len(str(context))
                },
                timestamp=datetime.now()
            )

            # Cache recent metrics
            cache_key = f"{agent_type}_{metrics.agent_id}"
            if cache_key not in self.performance_cache:
                self.performance_cache[cache_key] = []

            self.performance_cache[cache_key].append(metrics)

            # Keep only recent metrics
            if len(self.performance_cache[cache_key]) > 100:
                self.performance_cache[cache_key] = self.performance_cache[cache_key][-100:]

        except Exception as e:
            self.logger.error(f"Failed to record performance metrics: {e}")

    async def get_agent_recommendations(self, agent_type: str,
                                      current_context: Dict[str, Any]) -> List[str]:
        """Get personalized recommendations for an agent"""
        return await self.learning_system.get_recommendations(agent_type, current_context)

    async def predict_agent_success(self, agent_type: str, action_type: str,
                                  context: Dict[str, Any]) -> float:
        """Predict success probability for agent action"""
        return await self.learning_system.predict_success(agent_type, action_type, context)

    async def get_performance_insights(self, agent_type: str) -> Dict[str, Any]:
        """Get performance insights for an agent type"""
        try:
            insights = {
                'agent_type': agent_type,
                'recent_performance': {},
                'trends': {},
                'recommendations': []
            }

            # Get cached metrics
            relevant_metrics = []
            for cache_key, metrics_list in self.performance_cache.items():
                if agent_type in cache_key:
                    relevant_metrics.extend(metrics_list[-10:])  # Last 10 metrics

            if relevant_metrics:
                # Calculate recent performance
                avg_success = sum(m.success_rate for m in relevant_metrics) / len(relevant_metrics)
                avg_confidence = sum(m.confidence_score for m in relevant_metrics) / len(relevant_metrics)
                avg_execution_time = sum(m.execution_time for m in relevant_metrics) / len(relevant_metrics)

                insights['recent_performance'] = {
                    'average_success_rate': round(avg_success, 3),
                    'average_confidence': round(avg_confidence, 3),
                    'average_execution_time': round(avg_execution_time, 3),
                    'sample_size': len(relevant_metrics)
                }

                # Performance trends
                if len(relevant_metrics) >= 5:
                    recent_half = relevant_metrics[-len(relevant_metrics)//2:]
                    earlier_half = relevant_metrics[:-len(relevant_metrics)//2]

                    recent_success = sum(m.success_rate for m in recent_half) / len(recent_half)
                    earlier_success = sum(m.success_rate for m in earlier_half) / len(earlier_half)

                    trend = recent_success - earlier_success

                    insights['trends'] = {
                        'success_rate_trend': 'improving' if trend > 0.05 else 'declining' if trend < -0.05 else 'stable',
                        'trend_magnitude': round(trend, 3)
                    }

            # Get learning-based recommendations
            recommendations = await self.learning_system.get_recommendations(agent_type, {})
            insights['recommendations'] = recommendations

            return insights

        except Exception as e:
            self.logger.error(f"Failed to get performance insights: {e}")
            return {'error': str(e)}

    async def generate_learning_summary(self) -> Dict[str, Any]:
        """Generate comprehensive learning summary"""
        try:
            summary = await self.learning_system.generate_learning_report()

            # Add performance cache insights
            cache_summary = {}
            for agent_type in set(key.split('_')[0] for key in self.performance_cache.keys()):
                insights = await self.get_performance_insights(agent_type)
                cache_summary[agent_type] = insights

            summary['agent_performance'] = cache_summary

            return summary

        except Exception as e:
            self.logger.error(f"Failed to generate learning summary: {e}")
            return {'error': str(e)}

    async def optimize_agent_parameters(self, agent_type: str,
                                      current_params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize agent parameters based on learning"""
        try:
            # Get recent patterns for this agent type
            patterns = await self.learning_system.get_recent_patterns()

            optimized_params = current_params.copy()

            for pattern in patterns:
                if agent_type.lower() in pattern.description.lower():
                    if pattern.pattern_type == "high_success" and pattern.success_rate > 0.8:
                        # Apply successful pattern recommendations
                        for rec in pattern.recommendations:
                            if "timeout" in rec.lower() and "increase" in rec.lower():
                                if "timeout" in optimized_params:
                                    optimized_params["timeout"] *= 1.2

                            elif "threads" in rec.lower() and "parallel" in rec.lower():
                                if "threads" in optimized_params:
                                    optimized_params["threads"] = min(
                                        optimized_params["threads"] * 2, 10
                                    )

                            elif "comprehensive" in rec.lower():
                                optimized_params["comprehensive_mode"] = True

                    elif pattern.pattern_type == "low_success" and pattern.success_rate < 0.3:
                        # Apply failure pattern mitigations
                        for rec in pattern.recommendations:
                            if "alternative" in rec.lower():
                                optimized_params["fallback_enabled"] = True

                            elif "validation" in rec.lower():
                                optimized_params["validation_level"] = "strict"

            # Predict success with optimized parameters
            predicted_success = await self.learning_system.predict_success(
                agent_type, "optimize", optimized_params
            )

            return {
                'optimized_parameters': optimized_params,
                'predicted_success': predicted_success,
                'changes_made': [
                    key for key in optimized_params
                    if key not in current_params or optimized_params[key] != current_params[key]
                ]
            }

        except Exception as e:
            self.logger.error(f"Failed to optimize agent parameters: {e}")
            return {
                'optimized_parameters': current_params,
                'predicted_success': 0.5,
                'error': str(e)
            }

# Global learning integration instance
learning_integration = LearningIntegration(AdaptiveLearningSystem())