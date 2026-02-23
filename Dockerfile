FROM node:20-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install
RUN apk add --no-cache sqlite sqlite-libs

COPY . .

EXPOSE 3000

CMD ["node", "src/app.js"]
