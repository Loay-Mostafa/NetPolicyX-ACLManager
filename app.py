from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import sqlite3
import os
import datetime
import subprocess
import re
from werkzeug.serving import run_simple
from flask_restful import Api, Resource
from marshmallow import Schema, fields, validate, ValidationError

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'ultra-simple-secret-key'
app.config['DATABASE'] = 'netpolicyx.db'
api = Api(app)

# Marshmallow Schemas for validation
class DeviceSchema(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    ip_address = fields.Str(required=True, validate=validate.Regexp(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
        error='Invalid IP address format'
    ))

class ACLRuleSchema(Schema):
    device_id = fields.Int(required=True)
    action = fields.Str(required=True, validate=validate.OneOf(['permit', 'deny']))
    source = fields.Str(required=True, validate=validate.Regexp(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^any$',
        error='Invalid source format. Must be IP address or "any"'
    ))
    destination = fields.Str(required=True, validate=validate.Regexp(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^any$',
        error='Invalid destination format. Must be IP address or "any"'
    ))

device_schema = DeviceSchema()
acl_rule_schema = ACLRuleSchema()

# Database functions
def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create devices table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create ACL rules table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS acl_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        source TEXT NOT NULL,
        destination TEXT NOT NULL,
        is_applied INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (device_id) REFERENCES devices (id)
    )
    ''')
    
    # Create logs table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id INTEGER,
        operation TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (rule_id) REFERENCES acl_rules (id)
    )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database if it doesn't exist
if not os.path.exists(app.config['DATABASE']):
    init_db()

# Routes
@app.route('/')
def index():
    # Get devices
    conn = get_db_connection()
    devices = conn.execute('SELECT * FROM devices').fetchall()
    device_count = len(devices)
    
    # Get ACL rules
    rules = conn.execute('SELECT * FROM acl_rules').fetchall()
    rule_count = len(rules)
    
    # Get logs
    logs = conn.execute('SELECT * FROM logs ORDER BY created_at DESC LIMIT 5').fetchall()
    
    # Get conflicts
    conflicts = []
    for i, rule1 in enumerate(rules):
        for rule2 in rules[i+1:]:
            if rule1['device_id'] == rule2['device_id']:
                if (rule1['source'] == rule2['source'] or rule1['source'] == 'any' or rule2['source'] == 'any') and \
                   (rule1['destination'] == rule2['destination'] or rule1['destination'] == 'any' or rule2['destination'] == 'any') and \
                   rule1['action'] != rule2['action']:
                    conflicts.append({
                        'rule1_id': rule1['id'],
                        'rule2_id': rule2['id'],
                        'description': f"Conflict between Rule {rule1['id']} and Rule {rule2['id']}: different actions for overlapping traffic"
                    })
    
    conflict_count = len(conflicts)
    
    conn.close()
    
    return render_template('index.html', 
                          device_count=device_count, 
                          rule_count=rule_count, 
                          conflict_count=conflict_count,
                          devices=devices,
                          rules=rules,
                          logs=logs,
                          conflicts=conflicts)

# Device routes
@app.route('/devices')
def devices():
    conn = get_db_connection()
    devices = conn.execute('SELECT * FROM devices').fetchall()
    conn.close()
    return render_template('devices.html', devices=devices)

@app.route('/devices/add', methods=['GET', 'POST'])
def add_device():
    if request.method == 'POST':
        name = request.form['name']
        ip_address = request.form['ip_address']
        # Strong validation using Marshmallow
        errors = device_schema.validate({'name': name, 'ip_address': ip_address})
        if errors:
            flash(f"Error: {errors}")
            return render_template('add_device.html', name=name, ip_address=ip_address)
        conn = get_db_connection()
        conn.execute('INSERT INTO devices (name, ip_address) VALUES (?, ?)',
                    (name, ip_address))
        conn.commit()
        conn.close()
        flash('Device added successfully!')
        return redirect(url_for('devices'))
    return render_template('add_device.html')

@app.route('/devices/test/<int:id>')
def test_device(id):
    conn = get_db_connection()
    device = conn.execute('SELECT * FROM devices WHERE id = ?', (id,)).fetchone()
    conn.close()
    
    if device:
        # Simulation mode - always return success
        flash(f"Successfully connected to {device['name']} ({device['ip_address']})")
    else:
        flash('Device not found!')
    
    return redirect(url_for('devices'))

@app.route('/devices/delete/<int:id>')
def delete_device(id):
    conn = get_db_connection()
    
    # Check if device has ACL rules
    rules = conn.execute('SELECT * FROM acl_rules WHERE device_id = ?', (id,)).fetchall()
    if rules:
        flash('Cannot delete device with associated ACL rules!')
        conn.close()
        return redirect(url_for('devices'))
    
    conn.execute('DELETE FROM devices WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    flash('Device deleted successfully!')
    return redirect(url_for('devices'))

# ACL routes
@app.route('/acl')
def acl():
    conn = get_db_connection()
    rules = conn.execute('SELECT r.*, d.name as device_name FROM acl_rules r JOIN devices d ON r.device_id = d.id').fetchall()
    devices = conn.execute('SELECT * FROM devices').fetchall()
    conn.close()
    
    return render_template('acl.html', rules=rules, devices=devices)

@app.route('/acl/add', methods=['GET', 'POST'])
def add_rule():
    conn = get_db_connection()
    devices = conn.execute('SELECT * FROM devices').fetchall()
    if request.method == 'POST':
        device_id = request.form['device_id']
        action = request.form['action']
        source = request.form['source']
        destination = request.form['destination']
        # Strong validation using Marshmallow
        errors = acl_rule_schema.validate({
            'device_id': device_id,
            'action': action,
            'source': source,
            'destination': destination
        })
        if errors:
            flash(f"Error: {errors}")
            return render_template('add_rule.html', devices=devices, device_id=device_id, action=action, source=source, destination=destination)
        # Check device exists
        device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
        if not device:
            flash('Error: Device does not exist!')
            return render_template('add_rule.html', devices=devices, device_id=device_id, action=action, source=source, destination=destination)
        cursor = conn.execute('INSERT INTO acl_rules (device_id, action, source, destination) VALUES (?, ?, ?, ?)',
                    (device_id, action, source, destination))
        rule_id = cursor.lastrowid
        conn.execute('INSERT INTO logs (rule_id, operation) VALUES (?, ?)',
                    (rule_id, 'create'))
        conn.commit()
        conn.close()
        flash('ACL rule created successfully!')
        return redirect(url_for('acl'))
    conn.close()
    return render_template('add_rule.html', devices=devices)

@app.route('/acl/preview', methods=['POST'])
def preview_rule():
    action = request.form['action']
    source = request.form['source']
    destination = request.form['destination']
    
    # Generate a simple ACL command preview
    command = f"access-list 100 {action} ip {source} {destination}"
    
    return command

@app.route('/acl/apply/<int:id>')
def apply_rule(id):
    conn = get_db_connection()
    rule = conn.execute('SELECT * FROM acl_rules WHERE id = ?', (id,)).fetchone()
    
    if not rule:
        flash('Rule not found!')
        conn.close()
        return redirect(url_for('acl'))
    
    # Simulation mode - always return success
    conn.execute('UPDATE acl_rules SET is_applied = 1 WHERE id = ?', (id,))
    
    # Log the operation
    conn.execute('INSERT INTO logs (rule_id, operation) VALUES (?, ?)',
                (id, 'apply'))
    
    conn.commit()
    conn.close()
    
    flash('ACL rule applied successfully!')
    return redirect(url_for('acl'))

@app.route('/acl/remove/<int:id>')
def remove_rule(id):
    conn = get_db_connection()
    rule = conn.execute('SELECT * FROM acl_rules WHERE id = ?', (id,)).fetchone()
    
    if not rule:
        flash('Rule not found!')
        conn.close()
        return redirect(url_for('acl'))
    
    if not rule['is_applied']:
        flash('Rule is not currently applied!')
        conn.close()
        return redirect(url_for('acl'))
    
    # Simulation mode - always return success
    conn.execute('UPDATE acl_rules SET is_applied = 0 WHERE id = ?', (id,))
    
    # Log the operation
    conn.execute('INSERT INTO logs (rule_id, operation) VALUES (?, ?)',
                (id, 'remove'))
    
    conn.commit()
    conn.close()
    
    flash('ACL rule removed successfully!')
    return redirect(url_for('acl'))

@app.route('/acl/delete/<int:id>')
def delete_rule(id):
    conn = get_db_connection()
    rule = conn.execute('SELECT * FROM acl_rules WHERE id = ?', (id,)).fetchone()
    
    if not rule:
        flash('Rule not found!')
        conn.close()
        return redirect(url_for('acl'))
    
    if rule['is_applied']:
        flash('Cannot delete rule that is currently applied!')
        conn.close()
        return redirect(url_for('acl'))
    
    conn.execute('DELETE FROM acl_rules WHERE id = ?', (id,))
    
    # Log the operation
    conn.execute('INSERT INTO logs (rule_id, operation) VALUES (?, ?)',
                (id, 'delete'))
    
    conn.commit()
    conn.close()
    
    flash('ACL rule deleted successfully!')
    return redirect(url_for('acl'))

# Network testing routes
@app.route('/network')
def network():
    conn = get_db_connection()
    rules = conn.execute('SELECT * FROM acl_rules').fetchall()
    conn.close()
    
    return render_template('network.html', rules=rules)

@app.route('/network/ping', methods=['POST'])
def ping_test():
    host = request.form['host']
    
    if not host:
        flash('Host is required!')
        return redirect(url_for('network'))
    
    # Simple ping simulation
    is_reachable = True  # Simulate success
    output = f"PING {host} (8.8.8.8): 56 data bytes\n64 bytes from 8.8.8.8: icmp_seq=0 ttl=56 time=15.897 ms\n64 bytes from 8.8.8.8: icmp_seq=1 ttl=56 time=14.953 ms\n64 bytes from 8.8.8.8: icmp_seq=2 ttl=56 time=13.833 ms\n\n--- {host} ping statistics ---\n3 packets transmitted, 3 packets received, 0.0% packet loss\nround-trip min/avg/max/stddev = 13.833/14.894/15.897/0.839 ms"
    
    return render_template('ping_result.html', host=host, is_reachable=is_reachable, output=output)

@app.route('/network/validate', methods=['POST'])
def validate_acl():
    rule_id = request.form['rule_id']
    host = request.form['host']
    
    if not rule_id or not host:
        flash('Rule and host are required!')
        return redirect(url_for('network'))
    
    conn = get_db_connection()
    rule = conn.execute('SELECT * FROM acl_rules WHERE id = ?', (rule_id,)).fetchone()
    conn.close()
    
    if not rule:
        flash('Rule not found!')
        return redirect(url_for('network'))
    
    # Simulate before state (always reachable)
    before_reachable = True
    
    # Simulate after state based on rule action
    after_reachable = rule['action'] == 'permit'
    
    return render_template('validate_result.html', 
                          rule=rule, 
                          host=host, 
                          before_reachable=before_reachable, 
                          after_reachable=after_reachable)

# Logs and conflicts
@app.route('/logs')
def logs():
    conn = get_db_connection()
    logs = conn.execute('''
        SELECT l.*, r.action, r.source, r.destination, d.name as device_name
        FROM logs l
        JOIN acl_rules r ON l.rule_id = r.id
        JOIN devices d ON r.device_id = d.id
        ORDER BY l.created_at DESC
    ''').fetchall()
    conn.close()
    
    return render_template('logs.html', logs=logs)

@app.route('/conflicts')
def conflicts():
    conn = get_db_connection()
    rules = conn.execute('SELECT * FROM acl_rules').fetchall()
    
    conflicts = []
    for i, rule1 in enumerate(rules):
        for rule2 in rules[i+1:]:
            if rule1['device_id'] == rule2['device_id']:
                if (rule1['source'] == rule2['source'] or rule1['source'] == 'any' or rule2['source'] == 'any') and \
                   (rule1['destination'] == rule2['destination'] or rule1['destination'] == 'any' or rule2['destination'] == 'any') and \
                   rule1['action'] != rule2['action']:
                    # Get device name
                    device = conn.execute('SELECT name FROM devices WHERE id = ?', (rule1['device_id'],)).fetchone()
                    device_name = device['name'] if device else 'Unknown'
                    
                    conflicts.append({
                        'rule1': rule1,
                        'rule2': rule2,
                        'device_name': device_name,
                        'description': f"Conflict between rules: different actions for overlapping traffic"
                    })
    
    conn.close()
    
    return render_template('conflicts.html', conflicts=conflicts)

# RESTful API Resources
class DeviceResource(Resource):
    def get(self, device_id=None):
        try:
            conn = get_db_connection()
            if device_id is None:
                devices = conn.execute('SELECT * FROM devices').fetchall()
                return jsonify([{
                    'id': device['id'],
                    'name': device['name'],
                    'ip_address': device['ip_address'],
                    'created_at': device['created_at']
                } for device in devices])
            device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
            conn.close()
            if device is None:
                return {'error': 'Device not found'}, 404
            return jsonify({
                'id': device['id'],
                'name': device['name'],
                'ip_address': device['ip_address'],
                'created_at': device['created_at']
            })
        except Exception as e:
            return {'error': str(e)}, 500
    def post(self):
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No input data provided'}, 400
            errors = device_schema.validate(data)
            if errors:
                return {'error': errors}, 400
            conn = get_db_connection()
            cursor = conn.execute('INSERT INTO devices (name, ip_address) VALUES (?, ?)',
                                (data['name'], data['ip_address']))
            device_id = cursor.lastrowid
            conn.commit()
            device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
            conn.close()
            return {
                'id': device['id'],
                'name': device['name'],
                'ip_address': device['ip_address'],
                'created_at': device['created_at']
            }, 201
        except Exception as e:
            return {'error': str(e)}, 500
    def put(self, device_id):
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No input data provided'}, 400
            errors = device_schema.validate(data, partial=True)
            if errors:
                return {'error': errors}, 400
            conn = get_db_connection()
            device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
            if device is None:
                conn.close()
                return {'error': 'Device not found'}, 404
            updates = []
            values = []
            if 'name' in data:
                updates.append('name = ?')
                values.append(data['name'])
            if 'ip_address' in data:
                updates.append('ip_address = ?')
                values.append(data['ip_address'])
            if updates:
                values.append(device_id)
                query = f"UPDATE devices SET {', '.join(updates)} WHERE id = ?"
                conn.execute(query, values)
                conn.commit()
            device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
            conn.close()
            return {
                'id': device['id'],
                'name': device['name'],
                'ip_address': device['ip_address'],
                'created_at': device['created_at']
            }
        except Exception as e:
            return {'error': str(e)}, 500
    def delete(self, device_id):
        try:
            conn = get_db_connection()
            rules = conn.execute('SELECT * FROM acl_rules WHERE device_id = ?', (device_id,)).fetchall()
            if rules:
                conn.close()
                return {'error': 'Cannot delete device with associated ACL rules'}, 400
            conn.execute('DELETE FROM devices WHERE id = ?', (device_id,))
            conn.commit()
            conn.close()
            return '', 204
        except Exception as e:
            return {'error': str(e)}, 500

class ACLRuleResource(Resource):
    def get(self, rule_id=None):
        try:
            conn = get_db_connection()
            if rule_id is None:
                rules = conn.execute('''
                    SELECT r.*, d.name as device_name 
                    FROM acl_rules r 
                    JOIN devices d ON r.device_id = d.id
                ''').fetchall()
                return jsonify([{
                    'id': rule['id'],
                    'device_id': rule['device_id'],
                    'device_name': rule['device_name'],
                    'action': rule['action'],
                    'source': rule['source'],
                    'destination': rule['destination'],
                    'is_applied': bool(rule['is_applied']),
                    'created_at': rule['created_at']
                } for rule in rules])
            rule = conn.execute('''
                SELECT r.*, d.name as device_name 
                FROM acl_rules r 
                JOIN devices d ON r.device_id = d.id 
                WHERE r.id = ?
            ''', (rule_id,)).fetchone()
            conn.close()
            if rule is None:
                return {'error': 'Rule not found'}, 404
            return jsonify({
                'id': rule['id'],
                'device_id': rule['device_id'],
                'device_name': rule['device_name'],
                'action': rule['action'],
                'source': rule['source'],
                'destination': rule['destination'],
                'is_applied': bool(rule['is_applied']),
                'created_at': rule['created_at']
            })
        except Exception as e:
            return {'error': str(e)}, 500
    def post(self):
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No input data provided'}, 400
            errors = acl_rule_schema.validate(data)
            if errors:
                return {'error': errors}, 400
            conn = get_db_connection()
            device = conn.execute('SELECT id FROM devices WHERE id = ?', (data['device_id'],)).fetchone()
            if not device:
                conn.close()
                return {'error': 'Device not found'}, 404
            cursor = conn.execute('''
                INSERT INTO acl_rules (device_id, action, source, destination) 
                VALUES (?, ?, ?, ?)
            ''', (data['device_id'], data['action'], data['source'], data['destination']))
            rule_id = cursor.lastrowid
            conn.execute('INSERT INTO logs (rule_id, operation) VALUES (?, ?)',
                        (rule_id, 'create'))
            conn.commit()
            rule = conn.execute('''
                SELECT r.*, d.name as device_name 
                FROM acl_rules r 
                JOIN devices d ON r.device_id = d.id 
                WHERE r.id = ?
            ''', (rule_id,)).fetchone()
            conn.close()
            return {
                'id': rule['id'],
                'device_id': rule['device_id'],
                'device_name': rule['device_name'],
                'action': rule['action'],
                'source': rule['source'],
                'destination': rule['destination'],
                'is_applied': bool(rule['is_applied']),
                'created_at': rule['created_at']
            }, 201
        except Exception as e:
            return {'error': str(e)}, 500
    def put(self, rule_id):
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No input data provided'}, 400
            errors = acl_rule_schema.validate(data, partial=True)
            if errors:
                return {'error': errors}, 400
            conn = get_db_connection()
            rule = conn.execute('SELECT * FROM acl_rules WHERE id = ?', (rule_id,)).fetchone()
            if rule is None:
                conn.close()
                return {'error': 'Rule not found'}, 404
            updates = []
            values = []
            if 'action' in data:
                updates.append('action = ?')
                values.append(data['action'])
            if 'source' in data:
                updates.append('source = ?')
                values.append(data['source'])
            if 'destination' in data:
                updates.append('destination = ?')
                values.append(data['destination'])
            if updates:
                values.append(rule_id)
                query = f"UPDATE acl_rules SET {', '.join(updates)} WHERE id = ?"
                conn.execute(query, values)
                conn.commit()
            rule = conn.execute('''
                SELECT r.*, d.name as device_name 
                FROM acl_rules r 
                JOIN devices d ON r.device_id = d.id 
                WHERE r.id = ?
            ''', (rule_id,)).fetchone()
            conn.close()
            return {
                'id': rule['id'],
                'device_id': rule['device_id'],
                'device_name': rule['device_name'],
                'action': rule['action'],
                'source': rule['source'],
                'destination': rule['destination'],
                'is_applied': bool(rule['is_applied']),
                'created_at': rule['created_at']
            }
        except Exception as e:
            return {'error': str(e)}, 500
    def delete(self, rule_id):
        try:
            conn = get_db_connection()
            rule = conn.execute('SELECT * FROM acl_rules WHERE id = ?', (rule_id,)).fetchone()
            if rule is None:
                conn.close()
                return {'error': 'Rule not found'}, 404
            if rule['is_applied']:
                conn.close()
                return {'error': 'Cannot delete applied rule'}, 400
            conn.execute('DELETE FROM acl_rules WHERE id = ?', (rule_id,))
            conn.commit()
            conn.close()
            return '', 204
        except Exception as e:
            return {'error': str(e)}, 500

class LogResource(Resource):
    def get(self):
        try:
            conn = get_db_connection()
            logs = conn.execute('''
                SELECT l.*, r.action, r.source, r.destination 
                FROM logs l 
                LEFT JOIN acl_rules r ON l.rule_id = r.id 
                ORDER BY l.created_at DESC
            ''').fetchall()
            conn.close()
            return jsonify([{
                'id': log['id'],
                'rule_id': log['rule_id'],
                'operation': log['operation'],
                'created_at': log['created_at'],
                'rule_action': log['action'],
                'rule_source': log['source'],
                'rule_destination': log['destination']
            } for log in logs])
        except Exception as e:
            return {'error': str(e)}, 500

# Register API resources
api.add_resource(DeviceResource, '/api/devices', '/api/devices/<int:device_id>')
api.add_resource(ACLRuleResource, '/api/rules', '/api/rules/<int:rule_id>')
api.add_resource(LogResource, '/api/logs')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
