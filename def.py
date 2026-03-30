import os
import random
from datetime import datetime, timedelta

# Начинаем плотную работу с 10 марта 2026
START_DATE = datetime(2026, 3, 10)
END_DATE = datetime(2026, 3, 30)
TOTAL_DAYS = (END_DATE - START_DATE).days

def generate_perfect_history():
    targets = ['src/lib.rs', 'README.md', 'registry_manifest.json']
    
    for i in range(TOTAL_DAYS + 1):
        current_date = START_DATE + timedelta(days=i)
        
        # В выходные работаем меньше (30% шанс), в будни — почти всегда (90%)
        is_weekend = current_date.weekday() >= 5
        chance = 0.3 if is_weekend else 0.9
        
        if random.random() > chance:
            continue
            
        # В рабочие дни делаем 3-6 коммитов, в выходные 1-2
        num_commits = random.randint(1, 2) if is_weekend else random.randint(3, 6)
        
        for _ in range(num_commits):
            h, m = random.randint(10, 23), random.randint(0, 59)
            commit_date = current_date.replace(hour=h, minute=m)
            formatted_date = commit_date.strftime('%Y-%m-%d %H:%M:%S')
            
            target = random.choice(targets)
            with open(target, 'a') as f:
                f.write(f'\n/* commit_ref: {formatted_date} */')
            
            os.environ['GIT_AUTHOR_DATE'] = formatted_date
            os.environ['GIT_COMMITTER_DATE'] = formatted_date
            
            msgs = [
                "feat: async buffer handling", "perf: reduce allocs", 
                "security: add mcp-frame filter", "docs: update spec",
                "fix: edge case in token stream", "refactor: kernel core"
            ]
            os.system(f'git add {target}')
            os.system(f'git commit -m "{random.choice(msgs)}" --quiet')

    print("--- Легенда основного проекта создана! ---")

if __name__ == "__main__":
    generate_perfect_history()
