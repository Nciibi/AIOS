import re

with open('D:\\projects\\aios\\full plan bible\\Bible\\02-Core\\Brain\\Attention\\004-Salience.md', 'r', encoding='utf-8') as f:
    content = f.read()

lines = content.split('\n')
result = []
in_fake_block = False

for i, line in enumerate(lines):
    # Check for opening: single backtick + tab + "ypescript"
    if line.startswith('`\t') and 'ypescript' in line:
        # Replace opening with proper triple backtick
        result.append('```typescript')
        in_fake_block = True
        continue
    
    # Check for closing: standalone single backtick when we are in a fake block
    stripped = line.strip()
    if in_fake_block and stripped == '`':
        result.append('```')
        in_fake_block = False
        continue
    
    result.append(line)

with open('D:\\projects\\aios\\full plan bible\\Bible\\02-Core\\Brain\\Attention\\004-Salience.md', 'w', encoding='utf-8') as f:
    f.write('\n'.join(result))

print(f'Processed {len(lines)} lines, fixed code blocks')
