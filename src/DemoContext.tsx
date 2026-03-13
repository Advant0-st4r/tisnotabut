import React, { createContext, useContext, useState, useEffect } from 'react';

export interface DemoState {
  isActive: boolean;
  step: number;
  completedSteps: number[];
  datasetLoaded: boolean;
  insightsRevealed: boolean;
}

interface DemoContextType {
  demoState: DemoState;
  startDemo: () => void;
  advanceStep: (step: number) => void;
  completeDemo: () => void;
  setDatasetLoaded: (loaded: boolean) => void;
  setInsightsRevealed: (revealed: boolean) => void;
}

const DemoContext = createContext<DemoContextType | undefined>(undefined);

export const DemoProvider: React.FC<{ children: React.ReactNode, user?: any }> = ({ children, user }) => {
  const [demoState, setDemoState] = useState<DemoState>({
    isActive: false,
    step: 0,
    completedSteps: [],
    datasetLoaded: false,
    insightsRevealed: false,
  });

  const logDemoEvent = (eventType: string, step: number) => {
    fetch('/api/demo/event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: user?.id || 'demo_user', eventType, step })
    }).catch(console.error);
  };

  const startDemo = () => {
    setDemoState({ isActive: true, step: 1, completedSteps: [], datasetLoaded: false, insightsRevealed: false });
    logDemoEvent('demo_started', 1);
  };

  const advanceStep = (step: number) => {
    setDemoState(prev => {
      if (!prev.completedSteps.includes(prev.step)) {
        logDemoEvent('demo_step_completed', prev.step);
      }
      return {
        ...prev,
        step,
        completedSteps: [...prev.completedSteps, prev.step]
      };
    });
  };

  const completeDemo = () => {
    logDemoEvent('demo_finished', demoState.step);
    setDemoState({ isActive: false, step: 0, completedSteps: [], datasetLoaded: false, insightsRevealed: false });
  };

  const setDatasetLoaded = (loaded: boolean) => {
    setDemoState(prev => ({ ...prev, datasetLoaded: loaded }));
  };

  const setInsightsRevealed = (revealed: boolean) => {
    setDemoState(prev => ({ ...prev, insightsRevealed: revealed }));
  };

  return (
    <DemoContext.Provider value={{ demoState, startDemo, advanceStep, completeDemo, setDatasetLoaded, setInsightsRevealed }}>
      {children}
    </DemoContext.Provider>
  );
};

export const useDemo = () => {
  const context = useContext(DemoContext);
  if (context === undefined) {
    throw new Error('useDemo must be used within a DemoProvider');
  }
  return context;
};