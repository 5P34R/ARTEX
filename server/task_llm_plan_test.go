package server

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmpool"
	"github.com/Autumn-27/norma/llm"
)

// A ChatGPT plan refusal never advances the task chain (no silent switch to a
// paid profile), even past the failure-streak threshold. A durable refusal ends
// the call as an exhausted chain so the intent settles as blocked; a transient
// 503 passes through as an ordinary error.
func TestPlanRefusalNeverAdvancesTaskChain(t *testing.T) {
	resetLLMFailStreaksForTest()
	durable := fmt.Errorf("openai-responses: status 403: %s ChatGPT plan usage limit reached", llmpool.NoFailoverMarker)
	transient := fmt.Errorf("openai-responses: status 503: %s ChatGPT plan usage is temporarily unavailable", llmpool.NoFailoverMarker)
	for _, planErr := range []error{durable, transient} {
		exhaustCalls := 0
		hooks := taskLLMStreamHooks{
			current: func(ctx context.Context) (taskLLMSelection, error) {
				return taskLLMSelection{task: &Task{ID: "1"}, profileID: 7, revision: 1, provider: &failingProvider{err: planErr}}, nil
			},
			exhaust: func(sel taskLLMSelection, cause error) (db.TaskLLMTransition, error) {
				exhaustCalls++
				next := int64(8)
				return db.TaskLLMTransition{Advanced: true, NextProfileID: &next}, nil
			},
		}
		for i := 0; i < llmFailStreakThreshold+2; i++ {
			_, _, _, err := completeTaskLLM(context.Background(), "1", llm.CompletionRequest{}, hooks)
			if !errors.Is(err, planErr) {
				t.Fatalf("call %d: err=%v, want the plan refusal", i, err)
			}
			if wantExhausted := planErr == durable; isTaskLLMChainExhausted(err) != wantExhausted {
				t.Fatalf("call %d: chain exhausted=%v, want %v", i, isTaskLLMChainExhausted(err), wantExhausted)
			}
		}
		if exhaustCalls != 0 {
			t.Fatalf("plan refusal advanced the chain %d time(s)", exhaustCalls)
		}
	}
}

func TestPlanRefusalRetryRules(t *testing.T) {
	durable := fmt.Errorf("openai-responses: %s ChatGPT plan usage limit reached", llmpool.NoFailoverMarker)
	transient := fmt.Errorf("openai-responses: status 503: %s temporarily unavailable", llmpool.NoFailoverMarker)
	if isRetryableStreamError(durable) {
		t.Fatal("a durable plan refusal (even in-stream, with no status) must not be retried")
	}
	if !isRetryableStreamError(transient) {
		t.Fatal("a transient 503 plan error should be retried on the same provider")
	}
}
