export namespace main {
	
	export class Settings {
	    autostart: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Settings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.autostart = source["autostart"];
	    }
	}
	export class Status {
	    connected: boolean;
	    rpm: number;
	    field2: number;
	    cmds: Record<string, number>;
	    lastUpdate: number;
	    error: string;
	    temps: Record<string, number>;
	    mode: number;
	
	    static createFrom(source: any = {}) {
	        return new Status(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.connected = source["connected"];
	        this.rpm = source["rpm"];
	        this.field2 = source["field2"];
	        this.cmds = source["cmds"];
	        this.lastUpdate = source["lastUpdate"];
	        this.error = source["error"];
	        this.temps = source["temps"];
	        this.mode = source["mode"];
	    }
	}

}

