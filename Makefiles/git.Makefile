remote_info=$(shell git remote -v | head -n 1 | cut -d" " -f1)
ginit: ## git init
	rm -rf .git
	git init
	git add -A
	git commit -q -m "init"
	git remote add ${remote_info}
	git push -q --set-upstream origin master -f
p: ## github
	git add -A
	git commit -m "$(shell date '+%Y/%m/%d %H:%M:%S')"
	git push -uq origin $(shell git branch --show-current)
x: ## chmod +x **/*.sh
	@chmod +x **/*.sh
