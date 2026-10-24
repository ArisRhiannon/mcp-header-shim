FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY bin ./bin
COPY src ./src
USER node
EXPOSE 8787
ENTRYPOINT ["node", "bin/mcp-header-shim.js"]
CMD ["-c", "/config/shim.json"]
