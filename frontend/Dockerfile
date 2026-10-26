FROM node:22-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy frontend source code
COPY . .

# Run as non-root user
RUN chown -R node:node /app
USER node

EXPOSE 5173

# Start the Vite development server on all network interfaces
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
