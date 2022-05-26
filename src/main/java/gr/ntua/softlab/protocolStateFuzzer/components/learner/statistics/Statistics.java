package gr.ntua.softlab.protocolStateFuzzer.components.learner.statistics;

import de.learnlib.api.query.DefaultQuery;
import gr.ntua.softlab.protocolStateFuzzer.stateFuzzer.core.config.StateFuzzerEnabler;
import gr.ntua.softlab.protocolStateFuzzer.components.learner.config.LearnerConfig;
import gr.ntua.softlab.protocolStateFuzzer.components.sul.core.config.SulConfig;
import net.automatalib.words.Alphabet;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

/**
 * Statistics collected over the learning process.
 */
public class Statistics {
    protected String runDescription;
    protected int alphabetSize;
    protected int states;
    protected long learnResets;
    protected long learnInputs;
    protected long allResets;
    protected long allInputs;
    protected List<DefaultQuery<?, ?>> counterexamples;
    protected long duration;
    protected long lastHypResets;
    protected long lastHypInputs;
    protected boolean finished;
    protected List<HypothesisStatistics> hypStats;
    protected String reason;

    protected Statistics() {
        runDescription = "";
    }

    @Override
    public String toString() {
        StringWriter sw = new StringWriter();
        export(sw);
        return sw.toString();
    }

    public void export(Writer writer) {
        PrintWriter out = new PrintWriter(writer);
        out.println(runDescription);
        out.println("=== STATISTICS ===");
        out.println("Learning finished: " + finished);
        if (!finished) {
            out.println("Reason: " + reason);
        }
        out.println("Size of the input alphabet: " + alphabetSize);
        out.println("Number of states: " + states);
        out.println("Number of hypotheses: " + hypStats.size());
        out.println("Number of inputs: " + allInputs);
        out.println("Number of resets: " + allResets);
        out.println("Number of learning inputs: " + learnInputs);
        out.println("Number of learning resets: " + learnResets);
        out.println("Number of inputs up to last hypothesis: " + lastHypInputs);
        out.println("Number of resets up to last hypothesis: " + lastHypResets);
        out.println("Time it took to learn model: " + duration);
        out.println("Counterexamples:");
        int ind = 1;
        for (Object ce : counterexamples) {
            out.println("CE " + (ind++) + ":" + ce);
        }
        if (!hypStats.isEmpty()) {
            out.println("Number of inputs when hypothesis was generated: "
                    + hypStats.stream().map(s -> s.getSnapshot().getInputs()).toList());
            out.println("Number of resets when hypothesis was generated: "
                    + hypStats.stream().map(s -> s.getSnapshot().getResets()).toList());
            out.println("Time when hypothesis was generated: "
                    + hypStats.stream().map(s -> s.getSnapshot().getTime()).toList());

            List<HypothesisStatistics> invalidatedHypStates = new ArrayList<>(hypStats);
            if (invalidatedHypStates.get(invalidatedHypStates.size() - 1).getCounterexample() == null) {
                invalidatedHypStates.remove(invalidatedHypStates.size() - 1);
            }

            out.println("Number of inputs when counterexample was found: "
                    + invalidatedHypStates.stream().map(s -> s.getCounterexampleSnapshot().getInputs()).toList());
            out.println("Number of resets when counterexample was found: "
                    + invalidatedHypStates.stream().map(s -> s.getCounterexampleSnapshot().getResets()).toList());
            out.println("Time when counterexample was found: "
                    + invalidatedHypStates.stream().map(s -> s.getCounterexampleSnapshot().getTime()).toList());
        }
        out.close();
    }

    protected void generateRunDescription(StateFuzzerEnabler stateFuzzerEnabler, Alphabet<?> alphabet) {
        StringWriter sw = new StringWriter();
        PrintWriter out = new PrintWriter(sw);
        out.println("=== RUN DESCRIPTION ===");
        out.println("Learning Parameters");
        out.println("Alphabet: " + alphabet);

        LearnerConfig learnerConfig = stateFuzzerEnabler.getLearnerConfig();
        out.println("Learning Algorithm: " + learnerConfig.getLearningAlgorithm());
        out.println("Equivalence Algorithms: " + learnerConfig.getEquivalenceAlgorithms());
        out.println("Min Length: " + learnerConfig.getMinLength());
        out.println("Max Length: " + learnerConfig.getMaxLength());
        out.println("Random Length: " + learnerConfig.getRandLength());
        out.println("Max Depth: " + learnerConfig.getMaxDepth());
        out.println("Prob Reset: " + learnerConfig.getProbReset());
        out.println("Max Queries: " + learnerConfig.getNumberOfQueries());
        out.println("SUL Parameters");

        SulConfig sulConfig = stateFuzzerEnabler.getSulConfig();
        out.println("Protocol: " + sulConfig.getProtocolVersion());
        out.println("ResetWait: " + sulConfig.getResetWait());
        out.println("Timeout: " + sulConfig.getTimeout());
        if (sulConfig.getCommand() != null) {
            out.println("RunWait: " + sulConfig.getRunWait());
            out.println("Command: " + sulConfig.getCommand());
        }

        out.close();
        runDescription = sw.toString();
    }

    public String getRunDescription() {
        return runDescription;
    }

    public int getAlphabetSize() {
        return alphabetSize;
    }

    protected void setAlphabetSize(int alphabetSize) {
        this.alphabetSize = alphabetSize;
    }

    public int getStates() {
        return states;
    }

    protected void setStates(int states) {
        this.states = states;
    }

    public long getLearnResets() {
        return learnResets;
    }

    protected void setLearnResets(long learnResets) {
        this.learnResets = learnResets;
    }

    public long getLearnInputs() {
        return learnInputs;
    }

    protected void setLearnInputs(long learnInputs) {
        this.learnInputs = learnInputs;
    }

    public long getAllResets() {
        return allResets;
    }

    protected void setAllResets(long allResets) {
        this.allResets = allResets;
    }

    public long getAllInputs() {
        return allInputs;
    }

    public void setAllInputs(long allInputs) {
        this.allInputs = allInputs;
    }

    public long getDuration() {
        return duration;
    }

    public void setDuration(long duration) {
        this.duration = duration;
    }

    protected long getLastHypResets() {
        return lastHypResets;
    }

    protected void setLastHypResets(long lastHypResets) {
        this.lastHypResets = lastHypResets;
    }

    public long getLastHypInputs() {
        return lastHypInputs;
    }

    protected void setLastHypInputs(long lastHypInputs) {
        this.lastHypInputs = lastHypInputs;
    }

    protected void setCounterexamples(List<DefaultQuery<?, ?>> counterexamples) {
        this.counterexamples = counterexamples;
    }

    protected void setFinished(boolean finished, String reason) {
        this.finished = finished;
        this.reason = reason;
    }

    public void setHypStats(List<HypothesisStatistics> hypStats) {
        this.hypStats = hypStats;
    }
}