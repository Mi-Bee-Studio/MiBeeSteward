import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	build: {
		target: 'es2020',
		cssCodeSplit: true,
		rollupOptions: {
			output: {
				manualChunks(id) {
					if (id.includes('node_modules/echarts') || id.includes('node_modules/zrender')) {
						return 'echarts';
					}
					if (id.includes('node_modules')) {
						return 'vendor';
					}
				}
			}
		}
	}
});
