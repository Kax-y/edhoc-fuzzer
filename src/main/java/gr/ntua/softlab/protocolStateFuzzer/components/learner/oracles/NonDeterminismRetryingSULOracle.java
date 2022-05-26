package gr.ntua.softlab.protocolStateFuzzer.components.learner.oracles;

import de.learnlib.api.oracle.MembershipOracle.MealyMembershipOracle;
import de.learnlib.api.query.Query;
import net.automatalib.words.Word;

import java.io.Writer;

public class NonDeterminismRetryingSULOracle<I, O> extends MultipleRunsSULOracle<I, O> implements MealyMembershipOracle<I, O> {

    protected ObservationTree<I, O> cache;
    protected Word<I> precedingInput;

    public NonDeterminismRetryingSULOracle(MealyMembershipOracle<I, O> sulOracle, ObservationTree<I, O> cache,
                                           int retries, boolean probabilisticSanitization, Writer log) {
        super(retries, sulOracle, probabilisticSanitization, log);
        this.cache = cache;
    }

    public void processQuery(Query<I, Word<O>> q) {
        Word<O> originalOutput = sulOracle.answerQuery(q.getInput());
        Word<O> outputFromCache = cache.answerQuery(q.getInput(), true);
        Word<O> returnedOutput = originalOutput;
        if (!outputFromCache.equals(originalOutput.prefix(outputFromCache.length()))) {
            log.println("Output inconsistent with cache, rerunning membership query");
            log.println("Input: " + q.getInput().prefix(outputFromCache.length()));
            log.println("Unexpected output: " + returnedOutput);
            log.println("Cached output: " + outputFromCache);
            log.flush();
            try {
                returnedOutput = getCheckedOutput(q.getInput(), originalOutput);
            } catch (NonDeterminismException e) {
                e.setPrecedingInput(precedingInput);
                throw e;
            }
        }

        q.answer(returnedOutput.suffix(q.getSuffix().length()));
        precedingInput = q.getInput();
    }

    protected Word<O> getCheckedOutput(Word<I> input, Word<O> originalOutput) {
        Word<O> checkedOutput = super.getMultipleRunOutput(input);

        if (!checkedOutput.equals(originalOutput)) {
            log.println("Output changed following rerun");
            log.println("Input: " + input);
            log.println("Original output: " + originalOutput);
            log.println("New output: " + checkedOutput);
            log.flush();
        }
        return checkedOutput;
    }

}