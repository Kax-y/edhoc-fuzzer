package gr.ntua.softlab.edhocFuzzer;

import gr.ntua.softlab.edhocFuzzer.learner.EdhocAlphabetPojoXml;
import gr.ntua.softlab.edhocFuzzer.sul.EdhocSulClientDelegate;
import gr.ntua.softlab.edhocFuzzer.sul.EdhocSulServerDelegate;
import gr.ntua.softlab.protocolStateFuzzer.learner.alphabet.AlphabetBuilder;
import gr.ntua.softlab.protocolStateFuzzer.learner.alphabet.AlphabetBuilderStandard;
import gr.ntua.softlab.protocolStateFuzzer.learner.alphabet.xml.AlphabetSerializerXml;
import gr.ntua.softlab.protocolStateFuzzer.learner.config.LearningConfig;
import gr.ntua.softlab.protocolStateFuzzer.mapper.MapperBuilder;
import gr.ntua.softlab.protocolStateFuzzer.mapper.config.MapperConfig;
import gr.ntua.softlab.protocolStateFuzzer.stateFuzzer.StateFuzzer;
import gr.ntua.softlab.protocolStateFuzzer.stateFuzzer.StateFuzzerBuilder;
import gr.ntua.softlab.protocolStateFuzzer.stateFuzzer.StateFuzzerComposerStandard;
import gr.ntua.softlab.protocolStateFuzzer.stateFuzzer.StateFuzzerStandard;
import gr.ntua.softlab.protocolStateFuzzer.stateFuzzer.config.StateFuzzerClientConfig;
import gr.ntua.softlab.protocolStateFuzzer.stateFuzzer.config.StateFuzzerConfig;
import gr.ntua.softlab.protocolStateFuzzer.stateFuzzer.config.StateFuzzerConfigBuilder;
import gr.ntua.softlab.protocolStateFuzzer.stateFuzzer.config.StateFuzzerServerConfig;
import gr.ntua.softlab.protocolStateFuzzer.sul.WrappedSulBuilder;
import gr.ntua.softlab.protocolStateFuzzer.testRunner.TestRunner;
import gr.ntua.softlab.protocolStateFuzzer.testRunner.TestRunnerBuilder;
import gr.ntua.softlab.protocolStateFuzzer.testRunner.config.TestRunnerConfig;
import gr.ntua.softlab.protocolStateFuzzer.testRunner.config.TestRunnerEnabler;
import gr.ntua.softlab.protocolStateFuzzer.timingProbe.TimingProbe;
import gr.ntua.softlab.protocolStateFuzzer.timingProbe.TimingProbeBuilder;
import gr.ntua.softlab.protocolStateFuzzer.timingProbe.config.TimingProbeConfig;
import gr.ntua.softlab.protocolStateFuzzer.timingProbe.config.TimingProbeEnabler;

public class MultiBuilder implements StateFuzzerConfigBuilder, StateFuzzerBuilder, TestRunnerBuilder, TimingProbeBuilder {

    private AlphabetBuilder alphabetBuilder = new AlphabetBuilderStandard(
            new AlphabetSerializerXml<>(EdhocAlphabetPojoXml.class)
    );

    private MapperBuilder mapperBuilder = null;

    private WrappedSulBuilder wrappedSulBuilder = null;

    @Override
    public StateFuzzerClientConfig buildClientConfig() {
        return new StateFuzzerClientConfig(
                new LearningConfig(),
                new MapperConfig(),
                new TestRunnerConfig(),
                new TimingProbeConfig(),
                new EdhocSulServerDelegate()
        );
    }

    @Override
    public StateFuzzerServerConfig buildServerConfig() {
        return new StateFuzzerServerConfig(
                new LearningConfig(),
                new MapperConfig(),
                new TestRunnerConfig(),
                new TimingProbeConfig(),
                new EdhocSulClientDelegate()
        );
    }

    @Override
    public StateFuzzer build(StateFuzzerConfig stateFuzzerConfig) {
        return new StateFuzzerStandard(
                new StateFuzzerComposerStandard(stateFuzzerConfig, alphabetBuilder, mapperBuilder, wrappedSulBuilder)
        );
    }

    @Override
    public TestRunner build(TestRunnerEnabler testRunnerEnabler) {
        return new TestRunner(testRunnerEnabler, alphabetBuilder, mapperBuilder, wrappedSulBuilder);
    }

    @Override
    public TimingProbe build(TimingProbeEnabler timingProbeEnabler) {
        return new TimingProbe(timingProbeEnabler, alphabetBuilder, mapperBuilder, wrappedSulBuilder);
    }
}
