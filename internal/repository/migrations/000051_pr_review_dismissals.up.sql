-- Git Capsule B8: registro de revisiones descartadas con reviewDismiss (quien, por que, sobre que commit).
-- Forgejo solo guarda al descartador como la cuenta de servicio: este registro conserva la persona de Capsule.
CREATE TABLE IF NOT EXISTS pr_review_dismissals (
    id           uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id   uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    pr_number    int          NOT NULL,
    review_id    bigint       NOT NULL,
    reviewer     varchar(64)  NOT NULL DEFAULT '',
    review_state varchar(24)  NOT NULL DEFAULT '',
    commit_sha   varchar(64)  NOT NULL DEFAULT '',
    dismissed_by uuid         REFERENCES users(id) ON DELETE SET NULL,
    reason       text         NOT NULL,
    created_at   timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT chk_pr_review_dismissals_pr CHECK (pr_number > 0)
);
CREATE INDEX IF NOT EXISTS idx_pr_review_dismissals_pr ON pr_review_dismissals(project_id, pr_number, created_at);
