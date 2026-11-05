FROM node:10
USER root
COPY . /app
WORKDIR /app
RUN npm install
ENV NODE_ENV=development
CMD ["node", "server.js"]
