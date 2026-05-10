from trl import GRPOConfig, GRPOTrainer
from training.rewards import omnivuln_curriculum_reward

# Mock train_dataset for script structure
train_dataset = [] 

training_args = GRPOConfig(
    output_dir="runs/omnivuln-grpo",
    learning_rate=5e-6,
    per_device_train_batch_size=2,
    gradient_accumulation_steps=8,
    num_generations=4,
    max_prompt_length=4096,
    max_completion_length=2048,
    logging_steps=10,
    save_steps=200,
)

trainer = GRPOTrainer(
    model="Qwen/Qwen2.5-Coder-32B-Instruct",
    args=training_args,
    train_dataset=train_dataset,
    reward_funcs=[omnivuln_curriculum_reward],
)

if __name__ == "__main__":
    trainer.train()
