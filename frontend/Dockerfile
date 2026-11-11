FROM node:24-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM nginx/nginx-unprivileged:stable-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist/frontend/browser/ /usr/share/nginx/html/
COPY --from=build /app/dist/frontend/3rdpartylicenses.txt /usr/share/nginx/html/3rdpartylicenses.txt

EXPOSE 8080
