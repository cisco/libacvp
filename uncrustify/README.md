## Instructions for Uncrustify

This project uses Uncrustify as the linter for enforcing specific C code syntax rules.

You can find the rules in default.cfg.

Please make sure that any changes that you make adhere to these rules.
You can run the following command to do just that!
WARNING, this command will make changes to the files in place, so make sure to save any work that you don't want to be affected.
I.e. use "git add" to stage your current changes, "git stash" to save them, etc. before continuing.

Assuming current working directory is top of project:

`uncrustify --no-backup -c uncrustify/default.cfg src/acvp*.c src/acvp*.h app/app_main.c`

