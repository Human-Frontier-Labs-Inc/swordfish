/**
 * Circuit Breaker Implementation
 *
 * Provides protection against cascading failures by wrapping calls to external
 * services and monitoring for failures. When failures exceed a threshold,
 * the circuit "opens" and subsequent calls fail immediately without attempting
 * the operation.
 */

export enum CircuitState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN',
}

export interface CircuitBreakerConfig {
  failureThreshold?: number;
  successThreshold?: number;
  timeout?: number; // ms
  resetTimeout?: number; // ms
  onOpen?: (event: CircuitEvent) => void;
  onClose?: (event: CircuitEvent) => void;
  onHalfOpen?: (event: CircuitEvent) => void;
}

export interface CircuitEvent {
  name: string;
  state: CircuitState;
  timestamp: Date;
  stats: CircuitBreakerStats;
}

export interface CircuitBreakerStats {
  successCount: number;
  failureCount: number;
  rejectedCount: number;
  timeoutCount: number;
  consecutiveFailures: number;
  consecutiveSuccesses: number;
  successRate: number;
  stateTransitions: number;
  lastFailure?: Date;
  lastSuccess?: Date;
}

export interface AggregatedStats {
  totalCircuits: number;
  openCircuits: number;
  closedCircuits: number;
  halfOpenCircuits: number;
  totalSuccesses: number;
  totalFailures: number;
  totalRejections: number;
  totalTimeouts: number;
}

/**
 * Circuit Breaker implementation with configurable thresholds and timeouts
 */
export class CircuitBreaker {
  private name: string;
  private state: CircuitState = CircuitState.CLOSED;
  private config: Required<Omit<CircuitBreakerConfig, 'onOpen' | 'onClose' | 'onHalfOpen'>> & {
    onOpen?: (event: CircuitEvent) => void;
    onClose?: (event: CircuitEvent) => void;
    onHalfOpen?: (event: CircuitEvent) => void;
  };
  private stats: CircuitBreakerStats;
  private lastStateChange: number = Date.now();
  private stateTransitionCount = 0;

  constructor(name: string, config: CircuitBreakerConfig = {}) {
    if (!name || name.trim() === '') {
      throw new Error('Circuit name is required');
    }

    // Validate config
    if (
      (config.failureThreshold !== undefined && config.failureThreshold <= 0) ||
      (config.successThreshold !== undefined && config.successThreshold <= 0) ||
      (config.timeout !== undefined && config.timeout <= 0) ||
      (config.resetTimeout !== undefined && config.resetTimeout <= 0)
    ) {
      throw new Error('Invalid configuration');
    }

    this.name = name;
    this.config = {
      failureThreshold: config.failureThreshold ?? 5,
      successThreshold: config.successThreshold ?? 2,
      timeout: config.timeout ?? 30000,
      resetTimeout: config.resetTimeout ?? 60000,
      onOpen: config.onOpen,
      onClose: config.onClose,
      onHalfOpen: config.onHalfOpen,
    };

    this.stats = this.createEmptyStats();
  }

  getName(): string {
    return this.name;
  }

  getConfig(): CircuitBreakerConfig {
    return {
      failureThreshold: this.config.failureThreshold,
      successThreshold: this.config.successThreshold,
      timeout: this.config.timeout,
      resetTimeout: this.config.resetTimeout,
    };
  }

  getState(): CircuitState {
    // Check if we should transition from OPEN to HALF_OPEN
    if (this.state === CircuitState.OPEN) {
      const elapsed = Date.now() - this.lastStateChange;
      if (elapsed >= this.config.resetTimeout) {
        this.transitionTo(CircuitState.HALF_OPEN);
      }
    }
    return this.state;
  }

  getStats(): CircuitBreakerStats {
    const total = this.stats.successCount + this.stats.failureCount;
    return {
      ...this.stats,
      successRate: total > 0 ? this.stats.successCount / total : 0,
      stateTransitions: this.stateTransitionCount,
    };
  }

  resetStats(): void {
    this.stats = this.createEmptyStats();
  }

  reset(): void {
    this.stats.consecutiveFailures = 0;
    this.stats.consecutiveSuccesses = 0;
  }

  forceOpen(): void {
    this.transitionTo(CircuitState.OPEN);
  }

  forceClose(): void {
    this.transitionTo(CircuitState.CLOSED);
    this.stats.consecutiveFailures = 0;
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    const currentState = this.getState();

    // Reject if circuit is open
    if (currentState === CircuitState.OPEN) {
      this.stats.rejectedCount++;
      throw new Error('Circuit is open');
    }

    // Execute with timeout
    try {
      const result = await this.executeWithTimeout(fn);
      this.recordSuccess();
      return result;
    } catch (error) {
      this.recordFailure(error as Error);
      throw error;
    }
  }

  private async executeWithTimeout<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      let completed = false;

      const timeoutId = setTimeout(() => {
        if (!completed) {
          completed = true;
          this.stats.timeoutCount++;
          reject(new Error('Operation timed out'));
        }
      }, this.config.timeout);

      fn()
        .then((result) => {
          if (!completed) {
            completed = true;
            clearTimeout(timeoutId);
            resolve(result);
          }
        })
        .catch((error) => {
          if (!completed) {
            completed = true;
            clearTimeout(timeoutId);
            reject(error);
          }
        });
    });
  }

  private recordSuccess(): void {
    this.stats.successCount++;
    this.stats.consecutiveSuccesses++;
    this.stats.consecutiveFailures = 0;
    this.stats.lastSuccess = new Date();

    if (this.state === CircuitState.HALF_OPEN) {
      if (this.stats.consecutiveSuccesses >= this.config.successThreshold) {
        this.transitionTo(CircuitState.CLOSED);
      }
    } else if (this.state === CircuitState.CLOSED) {
      // Reset failure count on success in closed state
      this.stats.consecutiveFailures = 0;
    }
  }

  private recordFailure(error: Error): void {
    this.stats.failureCount++;
    this.stats.consecutiveFailures++;
    this.stats.consecutiveSuccesses = 0;
    this.stats.lastFailure = new Date();

    if (this.state === CircuitState.HALF_OPEN) {
      // Any failure in half-open immediately opens the circuit
      this.transitionTo(CircuitState.OPEN);
    } else if (this.state === CircuitState.CLOSED) {
      if (this.stats.consecutiveFailures >= this.config.failureThreshold) {
        this.transitionTo(CircuitState.OPEN);
      }
    }
  }

  private transitionTo(newState: CircuitState): void {
    const oldState = this.state;
    if (oldState === newState) return;

    this.state = newState;
    this.lastStateChange = Date.now();
    this.stateTransitionCount++;

    if (newState === CircuitState.HALF_OPEN) {
      this.stats.consecutiveSuccesses = 0;
    }

    const event: CircuitEvent = {
      name: this.name,
      state: newState,
      timestamp: new Date(),
      stats: this.getStats(),
    };

    // Emit events
    if (newState === CircuitState.OPEN && this.config.onOpen) {
      this.config.onOpen(event);
    } else if (newState === CircuitState.CLOSED && this.config.onClose) {
      this.config.onClose(event);
    } else if (newState === CircuitState.HALF_OPEN && this.config.onHalfOpen) {
      this.config.onHalfOpen(event);
    }
  }

  private createEmptyStats(): CircuitBreakerStats {
    return {
      successCount: 0,
      failureCount: 0,
      rejectedCount: 0,
      timeoutCount: 0,
      consecutiveFailures: 0,
      consecutiveSuccesses: 0,
      successRate: 0,
      stateTransitions: 0,
    };
  }
}

/**
 * Registry for managing multiple circuit breakers
 */
export class CircuitBreakerRegistry {
  private circuits: Map<string, CircuitBreaker> = new Map();

  get(name: string): CircuitBreaker | undefined {
    return this.circuits.get(name);
  }

  getOrCreate(name: string, config?: CircuitBreakerConfig): CircuitBreaker {
    let circuit = this.circuits.get(name);
    if (!circuit) {
      circuit = new CircuitBreaker(name, config);
      this.circuits.set(name, circuit);
    }
    return circuit;
  }

  remove(name: string): boolean {
    return this.circuits.delete(name);
  }

  listAll(): CircuitBreaker[] {
    return Array.from(this.circuits.values());
  }

  getAggregatedStats(): AggregatedStats {
    const circuits = this.listAll();
    const stats: AggregatedStats = {
      totalCircuits: circuits.length,
      openCircuits: 0,
      closedCircuits: 0,
      halfOpenCircuits: 0,
      totalSuccesses: 0,
      totalFailures: 0,
      totalRejections: 0,
      totalTimeouts: 0,
    };

    for (const circuit of circuits) {
      const state = circuit.getState();
      const circuitStats = circuit.getStats();

      if (state === CircuitState.OPEN) stats.openCircuits++;
      else if (state === CircuitState.CLOSED) stats.closedCircuits++;
      else if (state === CircuitState.HALF_OPEN) stats.halfOpenCircuits++;

      stats.totalSuccesses += circuitStats.successCount;
      stats.totalFailures += circuitStats.failureCount;
      stats.totalRejections += circuitStats.rejectedCount;
      stats.totalTimeouts += circuitStats.timeoutCount;
    }

    return stats;
  }

  resetAll(): void {
    for (const circuit of this.circuits.values()) {
      circuit.forceClose();
      circuit.resetStats();
    }
  }
}
