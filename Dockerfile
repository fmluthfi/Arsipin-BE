FROM node:22-slim

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY package.json ./
COPY prisma ./prisma
RUN npm install && npx prisma generate

COPY src ./src
COPY .env.example ./
ENV NODE_ENV=production
EXPOSE 4000
CMD ["sh", "-c", "npm run db:migrate && npm start"]
