# Netlify + Neon

1. Создай проект PostgreSQL в Neon и скопируй строку подключения
   из Connect. Для функций используй pooled connection string с SSL.
2. Для переноса существующих данных выполни в терминале (подставь URL Neon):

   ```sh
   pg_dump --dbname=netfly --no-owner --no-privileges --format=custom --file=/tmp/netfly-transfer.dump
   pg_restore --dbname='NEON_CONNECTION_STRING' --no-owner --no-privileges --exit-on-error /tmp/netfly-transfer.dump
   ```

   Импорт выполняй в пустую базу. При ошибке остановись и проверь вывод.
   Для новой пустой базы вместо импорта можно выполнить:

   ```sh
   DATABASE_URL='NEON_CONNECTION_STRING' NODE_ENV=production npm run db:migrate
   ```

3. Отправь исходники в GitHub. В Netlify импортируй этот репозиторий.
   Настройки публикации берутся из netlify.toml: public и netlify/functions.
   Отдельная сборка интерфейса не требуется.
4. До публикации добавь в Environment variables Netlify:
   - NODE_ENV=production
   - DATABASE_URL — строка подключения Neon
   - JWT_SECRET — длинный случайный секрет
   - RESEND_API_KEY
   - FROM_EMAIL — подтверждённый отправитель Resend
   - TMDB_API_KEY
   - OMDB_API_KEY
   - YOUTUBE_API_KEY

   Эти переменные должны быть доступны Functions. Не загружай .env в репозиторий.
5. Запусти deploy. Проверь вход, сохранение данных, поиск и прямой адрес /rated.
   После изменения переменных запускай новый deploy.

Сайт и API работают на одном домене; дополнительные CORS-настройки не нужны.
Локальный запуск по-прежнему: npm start.
На Netlify учитываются лимиты функций и передачи данных, в том числе постеров.
