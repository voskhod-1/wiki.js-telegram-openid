# wiki.js-telegram-openid
WikiJS Telegram OpenID auth module

How to use:
1. Download repo in the root directory(where your docker-compose.yaml) of your wiki
2. Add in compose yaml in your wiki service this line
   ```
   volumes:
      - ./modules/authentication/telegram:/wiki/server/modules/authentication/telegram
   ```
