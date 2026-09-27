FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy frontend source code
COPY . .

EXPOSE 5173

# Start the Vite development server on all network interfaces
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
