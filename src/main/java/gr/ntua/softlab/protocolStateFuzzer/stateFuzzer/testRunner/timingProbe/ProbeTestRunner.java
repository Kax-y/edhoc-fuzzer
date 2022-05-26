package gr.ntua.softlab.protocolStateFuzzer.stateFuzzer.testRunner.timingProbe;

import gr.ntua.softlab.protocolStateFuzzer.stateFuzzer.testRunner.core.TestRunner;
import gr.ntua.softlab.protocolStateFuzzer.stateFuzzer.testRunner.core.TestRunnerResult;
import gr.ntua.softlab.protocolStateFuzzer.stateFuzzer.testRunner.core.config.TestRunnerEnabler;
import gr.ntua.softlab.protocolStateFuzzer.components.learner.alphabet.AlphabetBuilder;
import gr.ntua.softlab.protocolStateFuzzer.components.sul.mapper.MapperBuilder;
import gr.ntua.softlab.protocolStateFuzzer.components.learner.abstractSymbols.AbstractInput;
import gr.ntua.softlab.protocolStateFuzzer.components.learner.abstractSymbols.AbstractOutput;
import gr.ntua.softlab.protocolStateFuzzer.components.sul.core.WrappedSulBuilder;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

public class ProbeTestRunner extends TestRunner {

    protected List<TestRunnerResult<AbstractInput, AbstractOutput>> control = null;

    public ProbeTestRunner(TestRunnerEnabler testRunnerEnabler, AlphabetBuilder alphabetBuilder,
                           MapperBuilder mapperBuilder, WrappedSulBuilder wrappedSulBuilder) {
        super(testRunnerEnabler, alphabetBuilder, mapperBuilder, wrappedSulBuilder);
    }

    public boolean isNonDeterministic(boolean controlRun) throws IOException {
        List<TestRunnerResult<AbstractInput, AbstractOutput>> results = super.runTests();
        Iterator<TestRunnerResult<AbstractInput, AbstractOutput>> itControl = null;

        if (!controlRun) {
            itControl = control.iterator();
        }

        for (TestRunnerResult<AbstractInput, AbstractOutput> result : results) {
            if (result.getGeneratedOutputs().size() > 1) {
                return true;
            }
            if (itControl != null && !(result.getGeneratedOutputs().equals(itControl.next().getGeneratedOutputs()))) {
                return true;
            }
        }

        if (controlRun) {
            control = results;
        }

        return false;
    }
}